import csv
import random
import subprocess
import boto3
import logging
import os
import pprint
import time
import paramiko

pp = pprint.PrettyPrinter(indent=4)
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

AWS_REGION = 'us-east-1'
region = boto3.setup_default_session(region_name=AWS_REGION) #set default region
profile_name = boto3.Session(profile_name=os.environ['BENCH_PROFILE_NAME']) #set correct profile

HOME = os.environ['HOME']
COMPLETED_BEHCHMARKS_FILE = HOME + '/network-mapping/benchmarking/finished_benchmarks'
SKU_FILE = HOME + '/network-mapping/benchmarking/sku_list.txt'
TARGET_CSV = HOME + '/network-mapping/benchmarking/results.csv'
HEADER = ['SOURCE_INSTANCE', 'DEST_INSTANCE', 'MIN_LATENCY', 'MAX_LATENCY', 'P50_LATENCY', 'P90_LATENCY', 'P99_LATENCY', 'MEAN_LATENCY', 'STDDEV_LATENCY', 'TCP_RR_TRANSACTION_RATE', 'TCP_STREAM_THROUGHPUT']

#NOTE the VPC should already be created. for SSH purposes from user's machine, should also
#include an igw and add it to the route table of the vpc
BENCHMARKING_VPC_ID = 'vpc-0a485f2e2501d6564' #to be changed by the user


def run_benchmarks(source_instance, dest_instance):
    """
    Run the TCP_RR and TCP_STREAM netperf tests and collect the data.

    @param source_ip, dest_ip: the source and destination ips for the EC2 instances
    @param source_type, dest_type: the instance types for the source and destination EC2 instances
    @returns 2 lines to add into a CSV file. Outputs as 2 elements in a list.
    """

    source_instance.reload()
    dest_instance.reload()
    key = paramiko.RSAKey.from_private_key_file('./benchmarking-A.pem')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    source_ip = source_instance.public_ip_address #source public ip
    dest_ip = dest_instance.private_ip_address #dest private ip

    source_type = source_instance.instance_type
    dest_type = dest_instance.instance_type

    n_tries = 10
    i = 0
    while i < n_tries:
        try:
            logging.warning("Connecting to {}".format(source_ip))
            client.connect(hostname=source_ip, username="ubuntu", pkey=key)
            break
        except:
            logging.warning("Unable to connect to {}".format(source_ip))
            i = i + 1
            time.sleep(5)
    if i == n_tries: #Means we can't connect
        return [-1, -1]

    tcp_rr_cmd = 'netperf -H {} -p 50000 -t tcp_rr -I 95,10 -P 0 -v 1 -- -d send -T TCP -O "MIN_LATENCY, MAX_LATENCY, P50_LATENCY, P90_LATENCY, P99_LATENCY, MEAN_LATENCY, STDDEV_LATENCY, THROUGHPUT"'.format(dest_ip)
    logging.warning("Running test {}".format(tcp_rr_cmd))
    stdin, stdout, stderr = client.exec_command(tcp_rr_cmd)

    tcp_rr_output = '{}\t\t{}\t\t'.format(source_type, dest_type) + stdout.read().decode()
    #print(tcp_rr_output)

    tcp_stream_cmd = 'netperf -H {} -p 50000 -t tcp_stream -I 95,10 -P 0 -v 1 -- -d send -T TCP -O "THROUGHPUT"'.format(dest_ip)
    logging.warning("Running test {}".format(tcp_stream_cmd))
    stdin, stdout, stderr = client.exec_command(tcp_stream_cmd)

    tcp_stream_output = '{}\t\t{}\t\t'.format(source_type, dest_type) + stdout.read().decode()

    # close the client connection once the job is done
    client.close()

    return [tcp_rr_output, tcp_stream_output] #Return the outputs as a list of 2 elements

def get_public_ip():
    logging.warning("Getting current ip")
    result = subprocess.check_output(['curl', 'ifconfig.co'])
    public_ip = result.decode('utf-8')[0:len(result)-1]
    logging.warning("Obtained ip: {}".format(public_ip))
    return public_ip

#Not necessary, since deleting VPCs is a huge pain. Just specify your VPC id as a global variable
def create_networking():
    """
    Create the benchmarking VPC along with two subnets, one for the source and one for the dest
    @RETURNS the vpc id of the newly-created VPC
    """
    ec2 = boto3.resource('ec2')
    logging.warning("Creating VPC")
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/24')
    vpc.create_tags(Tags=[{'Key': 'Name', 'Value': 'benchmarking-vpc'}])
    vpc.wait_until_available()
    vpc_id = vpc.id
    logging.warning("Successfully created VPC {}".format(vpc_id))
    logging.warning("Creating subnets")
    src_subnet = ec2.create_subnet(CidrBlock='10.0.0.0/25', VpcId=vpc_id)
    dest_subnet = ec2.create_subnet(CidrBlock='10.0.0.128/25', VpcId=vpc_id)
    logging.warning("Successfully created source subnet {} and destination subnet {}"
            .format(src_subnet.id, dest_subnet.id))
    return vpc_id

def create_access_sg(public_ip):
    """
    Creates a security group called benchmark_access_sg
    Adds an ingress rule allowing access from the ip of the machine running this script
    @RETURNS the id of the security group
    """
    cidr_ip = public_ip + '/32'
    logging.warning("Creating security group to allow access from {}".format(public_ip))
    ec2 = boto3.client('ec2')
    response = ec2.create_security_group(GroupName='benchmark_access_sg',
            Description="Allow access from running PC for testing and control purposes",
            VpcId=BENCHMARKING_VPC_ID)
    security_group_id = response['GroupId']
    
    logging.warning("Adding ingress rule for access from {}".format(cidr_ip))
    data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                'IpProtocol': '-1',
                'FromPort': -1,
                'ToPort': -1,
                'IpRanges': [{'CidrIp': cidr_ip}]
                },
            ])
    logging.warning("Created ingress rule for access from {}".format(cidr_ip))
    return security_group_id

def add_security_group(new_sg_id, instance_id):
    """
    Adds the security group to an existing instance. By adding, we don't destroy the default
    security group which is needed to allow communication between instances in the same VPC
    """
    ec2 = boto3.resource('ec2')
    instances = ec2.instances.filter()
    target = None
    for instance in instances:
        if instance.id == instance_id:
            target = instance
            break;
    sg_ids = [sg['GroupId'] for sg in target.security_groups]
    sg_ids.append(new_sg_id)
    logging.warning("Adding security group {} to instance {}".format(new_sg_id, instance_id))
    target.modify_attribute(Groups=sg_ids)
    logging.warning("Successfully added security group {} to instance {}"
            .format(new_sg_id, instance_id))
    

def create_keys(key_path_A, key_path_B):
    ec2 = boto3.resource('ec2')
    logging.warning("Creating Key Pairs")
    
    key_name_A = key_path_A
    key_name_B = key_path_B

    #create the keypair for instance A
    outfile = open(key_name_A+'.pem', 'w')
    response = ec2.create_key_pair(KeyName = key_name_A)
    kpo = str(response.key_material)
    logging.warning("Writing KeyPair A to {}".format(key_name_A+'.pem'))
    outfile.write(kpo)

    #create the keypair for instance B
    outfile = open(key_name_B+'.pem', 'w')
    response = ec2.create_key_pair(KeyName = key_name_B)
    kpo = str(response.key_material)
    logging.warning("Writing KeyPair B to {}".format(key_name_B+'.pem'))
    outfile.write(kpo)

    #chmod 400 both keypairs
    logging.warning("Running chmod 400 on both key pairs")
    os.system('chmod 400 {}'.format(key_name_A+'.pem'))    
    os.system('chmod 400 {}'.format(key_name_B+'.pem'))
    logging.warning("chmod Done")
    
    logging.warning("Finished creating keypairs")

def delete_sg(sg_id):
    logging.warning("Deleting security group {}".format(sg_id))
    ec2 = boto3.client('ec2')
    response = ec2.delete_security_group(GroupId=sg_id)
    logging.warning("Successfulyl deleted security group {}".format(sg_id))

def delete_keys(keyname):
    logging.warning("Deleting Key Pair")
    ec2 = boto3.client('ec2')
    response = ec2.delete_key_pair(KeyName=keyname)
    logging.warning("Successfully deletes keypair {}".format(keyname))

def attach_eip(instance_id):
    ec2 = boto3.client('ec2')
    logging.warning("Attaching EIP to instance {}".format(instance_id))
    allocation = ec2.allocate_address(Domain='vpc')
    response = ec2.associate_address(AllocationId=allocation['AllocationId'],
            InstanceId=instance_id)
    logging.warning("Attached EIP {} to instance {}".format(allocation['PublicIp'], instance_id))
    return allocation['PublicIP']

def detach_eip(allocation_id):
    ec2 = boto3.client('ec2')
    logging.warning("detaching allocation id {}".format(allocation_id))
    response = ec2.release_address(AllocationId=allocation_id)
    logging.warning("detached allocation id {}".format(allocation_id))

def allow_s3_access(instance_id):
    ec2 = boto3.client('ec2')
    logging.warning("Attaching S3 Access IAM role to instance {}".format(instance_id))
    response = ec2.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': 'arn:aws:iam::821921608777:instance-profile/NetworkBenchmarkingS3Access',
                    'Name': 'NetworkBenchmarkingS3Access'
                },
                InstanceId=instance_id
            )
    logging.warning("Successfully attached S3 Access IAM role to instance {}".format(instance_id))


def create_vms(source, dest, source_keyname, dest_keyname, 
        sg_id, ami_id, source_subnet_id, dest_subnet_id):
    """ 
    Takes the source and dest ec2 types and creates them through boto3
    Also requires the source keyname and dest keynames, in the form of their path.
    Returns the instance IDs in the form of [source_id, dest_id]    
    """

    ec2 = boto3.resource('ec2')

    """
    Create destination instance first
    wait for IP address to become available
    dest instance starts waiting for 5 seconds and then runnign the netperf server on p 50000

    Create source instance
    feed dest ip into user data
    source instance waits for 5 seconds before starting to benchmark dest instance
    """

    dest_user_data = """#!/bin/bash
                        netserver -p 50000
                    """
    logging.warning("Creating destination EC2 instance")
    response_dest = ec2.create_instances(
                ImageId = ami_id,
                MinCount = 1,
                MaxCount = 1,
                InstanceType = dest,
                NetworkInterfaces=[{
                    'SubnetId': dest_subnet_id,
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True,
                    }],
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [{
                        'Key': 'Name',
                        'Value': 'benchmark_destination'
                        }]
                    }],
                KeyName = dest_keyname,
                UserData = dest_user_data
            )

    for instance in response_dest:
        logging.warning("Launched destination instance {}".format(instance.id))
        add_security_group(sg_id, instance.id)
        logging.warning("Waiting for destination instance {} to be running".format(instance.id))
        instance.wait_until_running()
        logging.warning("Destination instance {} is in the running state".format(instance.id))
    
    logging.warning("Creating source EC2 instance")
    response_source = ec2.create_instances(
                ImageId = ami_id,
                MinCount = 1,
                MaxCount = 1,
                InstanceType = source,
                NetworkInterfaces=[{
                    'SubnetId': source_subnet_id,
                    'DeviceIndex': 0,
                    'AssociatePublicIpAddress': True,
                    }],
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [{
                        'Key': 'Name',
                        'Value': 'benchmark_source'
                        }]
                    }],
                KeyName = source_keyname
            )
    
    #loop throught the instances in response_source. Since MaxCount is 1, there should only be one
    #instance
    for instance in response_source:
        logging.warning("Launched instance {}".format(instance.id))
        add_security_group(sg_id, instance.id)
        logging.warning("Waiting for instance {} to be running".format(instance.id))
        instance.wait_until_running()
        logging.warning("Source instance {} is in the running state".format(instance.id))
        allow_s3_access(instance.id) #allow s3 access for the source instance

    logging.warning("Finished creating EC2 instances {}, {}".format(source, dest))

    return [response_source[0], response_dest[0]]

def put_guard_alarm(instance):
    """
    Create an alarm that terminates the instance if it's been active for more than 8 minutes
    """
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    cloudwatch = boto3.client('cloudwatch')
    cloudwatch.put_metric_alarm(
        AlarmName='{}_Guard_Alarm'.format(instance.id),
        AlarmDescription='Terminate benchmarking instance that was not terminated by the script for some reason',
        ComparisonOperator='GreaterThanThreshold',
        EvaluationPeriods=1,
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Period=600,
        Statistic='Average',
        Threshold=0.0,
        ActionsEnabled=True,
        AlarmActions=[
            'arn:aws:swf:{}:{}:action/actions/AWS_EC2.InstanceId.Terminate/1.0'.format(AWS_REGION, account_id)
        ],
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instance.id
            }
        ],
        Unit='Seconds'
    )

def delete_guard_alarm(instance):
    cloudwatch = boto3.client('cloudwatch')
    cloudwatch.delete_alarms(
        AlarmNames=['{}_Guard_Alarm'.format(instance.id)]
    )

def delete_vms(instances):
    client = boto3.client('ec2')
    logging.warning("Terminating instances {}, {}".format(instances[0].id, instances[1].id))
    response = client.terminate_instances(
        InstanceIds=[instance.id for instance in instances]
    )
    logging.warning("Terminated instances {}, {}".format(instances[0].id, instances[1].id))


def append_datasheet(results):
    #get results0 and results1, split by whitespace. contact the splits together, keeping only src and dest the same (no 2 sources and 2 dests)
    tcp_rr_results = results[0]
    tcp_stream_results = results[1]
    tcp_rr_results = tcp_rr_results.split()
    tcp_stream_results = tcp_stream_results.split()
    row = tcp_rr_results
    row.append(tcp_stream_results[2])
    print(row)
    with open(TARGET_CSV, 'a') as f:
        writer = csv.writer(f)
        writer.writerow(row)

if __name__ == "__main__":
    logging.warning("Starting Benchmarking")
    logging.warning("AWS_PROFILE set as {}".format(os.environ['AWS_PROFILE']))
   
    skus = []
    finished_benchmarks = []

    #get all the skus
    with open(SKU_FILE, 'r') as sku_file:
        skus = sku_file.read().splitlines()
        sku_file.close()

    #get all the completed benchmarks
    with open(COMPLETED_BEHCHMARKS_FILE, 'r') as completed_file:
        finished_benchmarks = [tuple(map(str, line.strip('\n').split('\t'))) for line in completed_file]
        completed_file.close()
    #Add a header if the file not not already have one. This is for when the user needs to stop the program temporarily and later continue
    #without writing a new header
    if not os.path.exists(TARGET_CSV):
        with open(TARGET_CSV, 'w', newline='') as outcsv:
            writer = csv.writer(outcsv)
            writer.writerow(HEADER)
    #########################################################
    #########################################################
    
    key_name_A = 'benchmarking-A' #source
    key_name_B = 'benchmarking-B' #destination
    #create_keys(key_name_A, key_name_B) #Create 2 keys, key A for the source and B for the dest
    #sg_id = create_access_sg(get_public_ip()) #Create sg to allow access from PC
    sg_id = 'sg-0a9401d64d3a21dff'
    ami_id = 'ami-02812ef5b1422d702' #the AMI to be used
    source_subnet_id = 'subnet-0e803edd9401bc805' #subnet 1
    dest_subnet_id = 'subnet-0ae5aeeed87402c4d' #subnet 2

    #TO CREATE MORE DIVERSE BENCHMARKING COMBOS
    pairs = []
    for source in skus:
        for dest in skus:
            pairs.append((source, dest))
    
    random.shuffle(pairs)
    completed_tests = []

    for (source, dest) in pairs:
        if (source, dest) in finished_benchmarks:
            print("{}, {} already has been run".format(source, dest))
            continue
        else:
            try:
                logging.warning("STARTING TEST FROM {} TO {}".format(source, dest))
                #TODO: create each VM by itself, and delete it by itself.
                instances = create_vms(source, dest, key_name_A, key_name_B, sg_id, ami_id, source_subnet_id, dest_subnet_id)
                #Create guard alarms
                put_guard_alarm(instances[0])
                put_guard_alarm(instances[1])
                results = run_benchmarks(instances[0], instances[1])
                delete_vms(instances)
                delete_guard_alarm(instances[0])
                delete_guard_alarm(instances[1])
                append_datasheet(results)

                #write to completed benchmarks file
                with open(COMPLETED_BEHCHMARKS_FILE, 'a') as f:
                    f.write("{}\t{}\n".format(source, dest))

                print('\n\n\n\n')
            except Exception as e:
                pp.pprint("Error with instances {}, {}".format(source, dest))
                print(e)
                delete_vms(instances)
                continue

    """
    ON DELETE:
        Delete keypairs from local machine
        Delete keypairs from AWS
        Destroy the EC2 instances
        Wait for both instances to be deleted before destroying security group
        Destroy the security group
    """

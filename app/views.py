from flask import request, jsonify
from app import app
import os
import csv
import pandas as pd
#assume we have data as a dict or something

@app.route('/')
def index():
    return "Prototype: Network Mapping APIs"

@app.route('/version')
def version():
    return 'v0.1'

@app.route('/limits', methods=["POST"])
def limit():
     input_json = request.get_json(force=True) 
     print(input_json)
     dictToReturn = {
        'src': input_json['src'], 
        'dst': input_json['dst'],
        'limit': 500,
        'unit': 'rps'}
     return jsonify(dictToReturn)

@app.route('/api/'+version()+'/us-east-1a/data', methods=["POST"])
def get_data():
    file_name = os.environ.get('PERFKIT_DATA_SOURCE') 
    input_json = request.get_json(force=True)
    links = input_json['links'] 
    print(links)
    limits = []

    tcp_throughput = "TCP_STREAM_Throughput"                          
    tcp_latency = "TCP_RR_Latency_p50"                                
    fields = ['source', 'destination', tcp_throughput, tcp_latency]   
    df = pd.read_csv(file_name, skipinitialspace=True, usecols=fields)

    for link in links:
        #loop through links in the json and get their TCP_RR throughput and latency
        src = link[0]
        dst = link[1]
        row = df.query('source == "{}" and destination == "{}"'.format(src, dst))
        if len(row) == 0:
            print("no answer found")
            limits.append([float(-1), float(-1)])
        else:
            limits.append([float(row[tcp_throughput]), float(row[tcp_latency])])

    dictToReturn = {
        'limits': limits,
        'tput_unit': 'RPS',
        'latency_unit': 'ms'
            }

    return jsonify(dictToReturn)

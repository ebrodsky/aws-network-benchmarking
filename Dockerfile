# Use the Python3.10.4 container image
FROM python:3.10.4-slim-bullseye

# Create an app directory
RUN mkdir /app

# Set the working directory to be /app
WORKDIR /app

# Copy the current dir contents into the container at /app
ADD . /app

# Install the dependencies
RUN pip install -r requirements.txt

EXPOSE 5000

# Run the command to start application
CMD ["python", "run.py"]
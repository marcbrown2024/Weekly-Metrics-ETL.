# import the required libraries

from urllib import response
import boto3
import email
from datetime import date
import pandas as pd
import json
from json import JSONDecodeError
import pymysql
import pymysql.cursors
from pprint import pprint
from io import BytesIO
import urllib.parse

# -----------------------------------------------------------------------------------

# get file bytes from downloaded email file from s3 bucket


def get_s3_file_bytes(fn, bucketname):

    s3_client = boto3.client('s3')

    response = None

    try:
        response = s3_client.get_object(Bucket=bucketname, Key=fn)

    except Exception as e:
        print(f"Error: {e}")

    pprint("Package recieved")

    return response['Body'].read()

# -----------------------------------------------------------------------------------

#  extract attachment(csv file) from email file


def extract_email_attachment(email_object):

    attachment_bytes = None

    for payload in email_object.get_payload():
        for part in payload.walk():
            if part.get_content_type() == "content/unknown":
                attachment_bytes = part.get_payload(decode=True)

    pprint("Attachment extracted")

    return attachment_bytes

# -----------------------------------------------------------------------------------

# function to parse email


def parsing_eml(eml_filename, s3_bucket):

    email_bytes = get_s3_file_bytes(
        fn=eml_filename,
        bucketname=s3_bucket
    )

    email_object = email.message_from_bytes(email_bytes)

    attachment_bytes = extract_email_attachment(email_object=email_object)

    df = pd.read_csv(BytesIO(attachment_bytes))
    if ("Threat Type" in str(df)):
        pprint("Files with Threat type data has been parsed successfully")
    elif ("Threat Target Host Name" in str(df)):
        pprint("Files with Threat Target Host Name data has been parsed successfully")
    elif ("Threat Name" in str(df)):
        pprint("Files with Threat Name data has been parsed successfully")

    return(df)
# -----------------------------------------------------------------------------------

# using pandas to transform the data from the csv file into a tuple to insert into the database


def data_transformation(fn):

    data_list = []
    constant_row = 'Number of Threat Events'

    if ("Threat Type" in str(fn)):

        for index, row in fn.iterrows():
            data_tuple = (row['Threat Type'],
                          row['Event Generated Time'],
                          row[constant_row], date.today())
            data_list.append(data_tuple)
        pprint("Parsed file with threat type data apended correctly")

    elif ("Threat Target Host Name" in str(fn)):

        for index, row in fn.iterrows():
            data_tuple = (row['Threat Target Host Name'],
                          row[constant_row], date.today())
            data_list.append(data_tuple)
        pprint("Parsed file with threat target host name data apended correctly")

    elif ("Threat Name" in str(fn)):

        for index, row in fn.iterrows():
            data_tuple = (row['Threat Name'],
                          row[constant_row], date.today())
            data_list.append(data_tuple)
        pprint("Parsed file with threat name data apended correctly")

    return data_list


# -----------------------------------------------------------------------------------

# accessing the aws secret manager for secret to access TAREPS database


def get_secret_from_sm(secret_name, region_name='us-east-1'):

    session = boto3.session.Session()

    sm_client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        endpoint_url=f"https://secretsmanager.{region_name}.amazonaws.com"
    )

    secret = ""
    secret_value_response = sm_client.get_secret_value(
        SecretId=secret_name
    )

    if 'SecretString' in secret_value_response:
        secret = secret_value_response['SecretString']

    try:
        return json.loads(secret)
    except JSONDecodeError:
        return secret

# -----------------------------------------------------------------------------------

# connect to database


def connect_to_db(hostname, username, password, database):
    return pymysql.connect(host=hostname, user=username, password=password, database=database,
                           connect_timeout=120, autocommit=True, cursorclass=pymysql.cursors.DictCursor)

# -----------------------------------------------------------------------------------

# load threat data from attached csv file into database


def load_database_data(db_connection, data_tuple_list, tablename):

    if (tablename == "epo_top_detected_hostname"):
        query = f"""
        INSERT INTO `{tablename}`
            (`threat_target_host_name`, `number_of_threat_events`, `program_run_date`)
        VALUES
            (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            `threat_target_host_name` = VALUES(`threat_target_host_name`),
            `number_of_threat_events` = VALUES(`number_of_threat_events`),
            `program_run_date` = VALUES(`program_run_date`)
            """
        pprint(
            "Conection successfully. Top detected host name data loaded into database.")

    elif (tablename == "epo_top_threat_names"):
        query = f"""
        INSERT INTO `{tablename}`
            (`threat_names`, `number_of_threat_events`, `program_run_date`)
        VALUES
            (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            `threat_names` = VALUES(`threat_names`),
            `number_of_threat_events` = VALUES(`number_of_threat_events`),
            `program_run_date` = VALUES(`program_run_date`)
            """
        pprint("Conection successfully. Top threat names data loaded into database.")

    elif (tablename == "epo_top_threat_types"):
        query = f"""
        INSERT INTO `{tablename}`
            (`threat_type`, `event_generated_time`, `number_of_threat_events`, `program_run_date`)
        VALUES
            (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            `threat_type` = VALUES(`threat_type`),
            `event_generated_time` = VALUES(`event_generated_time`),
            `number_of_threat_events` = VALUES(`number_of_threat_events`),
            `program_run_date` = VALUES(`program_run_date`)
            """
        pprint("Conection successfully. Top threat types data loaded into database.")

    with db_connection.cursor() as cursor:
        response = cursor.executemany(query, data_tuple_list)
        print(f'Response: {response}')

# -----------------------------------------------------------------------------------

# function with if statement to decide which table in database to upload data into


def table_opt(csv_file, db_connection, data):

    if ("Threat Target Host Name" in str(csv_file)):
        load_database_data(
            db_connection=db_connection, data_tuple_list=data, tablename='epo_top_detected_hostname')
    elif ("Threat Name" in str(csv_file)):
        load_database_data(
            db_connection=db_connection, data_tuple_list=data, tablename='epo_top_threat_names')
    elif ("Threat Type" in str(csv_file)):
        load_database_data(
            db_connection=db_connection, data_tuple_list=data, tablename='epo_top_threat_types')

    pprint("Program finished")

# -----------------------------------------------------------------------------------

# main function that runs the different functions needed to insert data into database


def run(event, context):

    s3_filename = urllib.parse.unquote_plus(
        event["Records"][0]["s3"]["object"]["key"], encoding="utf8")

    bucketname = event["Records"][0]["s3"]["bucket"]["name"]

    secret_manager_output = get_secret_from_sm(
        secret_name='prod/tareps/mysql/ingest', region_name='us-east-1')

    db_connection = connect_to_db(
        hostname=secret_manager_output['host'],
        username=secret_manager_output['username'],
        password=secret_manager_output['password'],
        database=secret_manager_output['database']
    )

    pprint("Database connection established")

    csv_file = parsing_eml(eml_filename=s3_filename, s3_bucket=bucketname)

    data = data_transformation(fn=csv_file)

    table_opt(csv_file, db_connection, data)


# Empty line

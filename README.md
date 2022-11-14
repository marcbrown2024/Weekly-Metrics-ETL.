# Introduction/Purpose

A scheduled ETL to automate the process of the manual weekly REPH Security Report using AWS SES, S3 & Lambda to ingest data from security tools into the TAREPS database to be presented on a visualization dashboard using visualization software.

# Course of Action

I. Familiarize with the security tool and the reports it outputs regarding security issues.

II. Set up email access to receive reports from security tools.

III. Receive data from security tools email through AWS SES.

IV. Email file to be transferred to a specific S3 bucket for weekly security tool reports.

V. File being transferred to S3 bucket acts as a switch to start a python script.

VI. Python script - script will use Pandas, boto3, json, pymysql and additional tools to read in and process csv file from AWS S3 bucket and load into TAREPS database.

VII. Test Infrastructure as code for Lambda then deploy the finished Lambda/python script using Linux subsystem and serverless.

VIII. Install and use visualization software to present the data in database with a similar fashion as the weekly REPH Security Report.

Software dependencies

I. PowerBI or similiar visualization software

II. Linux subsystem



# Objective 1: Download CloudTrail Logs

mkdir -p flaws2logs
aws s3 sync s3://flaws2-logs flaws2logs


# Objective 2: Access the Target Account

aws --profile target_security sts get-caller-identity


# Objective 3: Use jq for Investigation
1. Installation of jq

sudo apt-get install jq

2. Navigate into the logs file directory

cd flaws2logs/AWSLogs/653711331788/CloudTrail/us-east-1/2018/11/28/

3. Find all files in every subdirectory, recursively, and attempt to gunzip them

find . -type f -name '*.gz' -exec gunzip {} \;

4. Cat them through jq

find . -type f -exec cat {} \; | jq .

5. Filter event names with timestamps

find . -type f -exec cat {} \; | jq -cr '.Records[]|[.eventTime, .eventName]|@tsv' | sort


# Objective 4: Identify credential theft
1. Investigate the ListBuckets API call

find . -type f -exec cat {} \; | jq '.Records[]|select(.eventName=="ListBuckets")'

2. Additional investigation for the Role/User that performed the action

find . -type f -exec cat {} \; | jq '.Records[]|select(.roleArn=="arn:aws:iam::653711331788:role/level3")'

3. Check if the observed source IP address is AWS owned
4. Replace 104.102.221.250 with the actual observed source IP address

aws ec2 describe-addresses --filters "Name=public-ip,Values=104.102.221.250"


# Objective 5: Identify the public resource
1. Investigate ListImages API Calls

find . -type f -exec cat {} \; | jq '.Records[]|select(.eventName=="ListImages")'

2. Investigate BatchGetImage API Calls

find . -type f -exec cat {} \; | jq '.Records[]|select(.eventName=="BatchGetImage")'

3. Investigate GetDownloadUrlForLayer API Calls

find . -type f -exec cat {} \; | jq '.Records[]|select(.eventName=="GetDownloadUrlForLayer")'


# Lessons Learned

Lesson 1: Importance of CloudTrail Logs
CloudTrail logs provide a detailed record of AWS account activity.

Lesson 2: Effective Use of jq
jq is a powerful tool for querying and manipulating JSON data, enhancing log analysis capabilities.

Lesson 3: Incident Response Practices
Understand how to investigate security incidents, identify unauthorized API calls, and respond effectively.

Lesson 4: Role and IP Address Verification
Verify the legitimacy of roles and user actions, checking IP addresses for AWS ownership.

Lesson 5: API Call Investigation
Investigate specific API calls like ListBuckets, ListImages, BatchGetImage, and GetDownloadUrlForLayer.

Lesson 6: Continuous Monitoring
Establish the importance of continuous monitoring for potential security threats in an AWS environment.

I also learned that I can use AWS Athena for more advanced and interactive querying of CloudTrail logs.





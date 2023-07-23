#!/bin/bash

image_name="asia-northeast2-docker.pkg.dev/icscoe-2021/bb-docker-ar/harvester:latest"
service_account="bb-harvester-service@icscoe-2021.iam.gserviceaccount.com"
label="owner=bb"
max_retries="2" 
task_timeout="5m"
env_secrets="secrets_gcloud.yml"
cpu="1"
ram="2Gi"

job_count=5

for job in $(seq 0 ${job_count})
do
    job_name="bb-harvester-job-${job}"
    region=`shuf -n 1 gcloud.regions`
    echo -e "\n$(tput setaf 10)[*] $(tput setaf 6)${job_name}@${region}\n"
    echo -en "\033[0;90m"
    gcloud run jobs create ${job_name} \
        --service-account=${service_account} \
        --image=${image_name} \
        --labels=${label} \
        --max-retries=${max_retries} \
        --task-timeout=${task_timeout} \
        --region=${region} \
        --env-vars-file=${env_secrets} \
        --execute-now \
        --cpu=${cpu} --memory=${ram} \
        --command="/harvester/harvester.py"
    # gcloud run jobs delete ${job_name} --region=${region} --quiet --no-async
    echo -en "\033[0m"
done
#!/bin/bash

image_name="asia-docker.pkg.dev/jsps-deploy/bb-docker-ar-1/harvester:latest"
service_account="bb-harvester-service-1@jsps-deploy.iam.gserviceaccount.com"
project_name="jsps-deploy"
label="owner=bb"
max_retries="1" 
task_timeout="24h"
env_secrets="../secrets/secrets.yml"
cpu="1"
ram="4Gi"
job_counter=0

while read region
do
    job_rnd=`head -c 500 /dev/urandom | tr -dc 'a-z0-9' | fold -w 4 | head -n 1`
    job_name="bb-harvester-job-${job_counter}-${job_rnd}"
    echo -e "\n$(tput setaf 10)[*] $(tput setaf 6)${job_name}@${region}\n"
    jq --arg value ${region} '.connector.ip_region = $value' profile.json | sponge profile.json
    echo -en "\033[0;90m"
    gcloud run jobs create ${job_name} \
        --service-account=${service_account} \
	--project=${project_name} \
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
    ((job_counter = job_counter +1))
done < gcloud.global

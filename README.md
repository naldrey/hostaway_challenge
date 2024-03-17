# hostaway_challenge

## High Level Arquitecture Diagram

The architecture is structured around ECS and RDS, utilizing Terraform to establish the runtime, database, and essential resources like VPC, CDN, ALB, ECR, and Route53 Records. While the ECS service definition is in place, the task definition is not yet established, as it will be deployed on AWS through the GitHub actions outlined in the CI/CD pipeline section

![image](https://github.com/naldrey/hostaway_challenge/assets/53922947/edcac3ba-d6de-4418-88f2-6531e5580df1)

## CI/CD Pipeline
The CI/CD pipeline is developed using GitHub Actions, which triggers upon committing changes. Its logic is structured to first conduct a linting check on the Dockerfile to detect errors and potential enhancements. Following this, the pipeline proceeds to authenticate with AWS and the ECR associated with our service. Next, it builds the image and pushes it to the defined ECR repository. Finally, another step updates the task definition in ECS with the new image tag.

![image](https://github.com/naldrey/hostaway_challenge/assets/53922947/a4241963-8e6e-4cc3-abc5-2c10d9e68e8f)

## TO DO
- Improve testing with docker-compose
- Enhance build and push action
  - Enabling cache
  - Multiarch build



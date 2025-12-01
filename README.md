# CloudSec Guardian

Automated Cloud Infrastructure Deployment and Threat Monitoring System for AWS.

CloudSec Guardian securely deploys AWS resources (S3, EC2, Security Groups) and monitors real-time CloudTrail logs for suspicious security events. Built as part of a cloud cybersecurity research project.

---

## Current Features

✔ Secure S3 bucket creation with restricted public access  
✔ EC2 instance deployment with access control  
✔ CloudTrail automatic event logging  
✔ Threat detection for high-risk operations  
✔ Severity scoring for alerts  
✔ User attribution using CloudTrail identity logs  
✔ Logging & forensic trace support  
✔ Duplicate alert prevention with timestamp tracking  

---

## Tech Stack

Cloud Platform: AWS (Free Tier) 
Compute: EC2 (t2.micro) 
Storage & Logging: S3 + CloudTrail 
Security: IAM / VPC Security Groups 
Programming: Python 3.13 
Libraries: boto3 
OS: Linux (Arch) 
Version Control: Git + GitHub 

---

##  Architecture (Current Phase)


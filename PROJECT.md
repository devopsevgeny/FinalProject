# DevOps Final Project Proposal – Secure Configuration and Secret Management System

## Project Title
Secure Configuration and Secret Management System (ConfMgr)

---

## Project Description
The project will implement a **secure configuration and secret management system** for containerized applications.  
It will include:  
- A **PostgreSQL database** for storing secrets and audit logs.  
- A **Python FastAPI backend** to provide REST endpoints for secret management.  
- Scripts for encryption/decryption of secrets (AES-256-GCM).  
- **Docker Compose** for local development.  
- **Helm charts** for Kubernetes deployment.  
- **CI/CD pipeline** to automate build, testing, and deployment.  

This system solves the common DevOps challenge of **secure secret storage and distribution**.  

---

## Goals
- Demonstrate **scripting skills** using **Bash** (environment generators, seeders) and **Python** (backend).  
- Apply **DevOps practices**: version control, CI/CD, IaC, containerization, orchestration.  
- Produce a **working release** with downloadable and usable components.  
- Provide **documentation and troubleshooting guides**.  

---

## Planned Features
1. **Core system**  
   - Store encrypted secrets with versioning.  
   - Manage API clients (client ID, secret, issuer).  
   - Mutual TLS authentication for PostgreSQL.  
   - Audit logging of all secret access.  

2. **Tooling and Scripting**  
   - `gen_env.sh` – generates `.env` from template with random keys.  
   - Database seed scripts for clients.  
   - Demo Python script for secret roundtrip (encrypt → store → decrypt).  

3. **CI/CD pipeline**  
   - **CI**: GitHub Actions to pull repo, build Docker image, run tests, and release artifacts.  
   - **CD**: Automatic deployment to a Kubernetes cluster with Helm.  

4. **Infrastructure as Code (IaC)**  
   - Kubernetes manifests + Helm charts.  
   - Compose for local dev/test environment.  

5. **Documentation**  
   - `/doc` folder with guides:  
     - Setup & installation.  
     - CI/CD pipeline usage.  
     - Troubleshooting (e.g. SSL errors, DB migrations).  
     - Design notes (schemas, security model).  

---

## Tools, Dependencies & Libraries
- **Languages**: Python 3.12, Bash  
- **Frameworks**: FastAPI, SQLAlchemy  
- **Database**: PostgreSQL 16 (with pgcrypto)  
- **Libraries**: psycopg2, cryptography, bcrypt  
- **Containerization**: Docker, Docker Compose  
- **Orchestration**: Kubernetes, Helm  
- **CI/CD**: Jenkins or maybe GitHub Actions or GitLab CI 
- **IaC**: Helm charts, Kubernetes manifests  

---

## Version Control Strategy
- Repository hosted on GitHub  
- **GitHub Flow** branching model:  
  - `main` branch for stable releases  
  - Feature branches with pull requests  
  - CI validation before merge  

---

## Deliverables
- A working **Dockerized application** deployable with Compose or Helm  
- CI/CD pipeline with automated build, test, and deployment  
- Documentation in `/doc` folder: setup, usage, troubleshooting  
- A **release version** that can be downloaded and run  

---

## Learning Outcomes
By completing this project, I will demonstrate:  
- Secure system design with encryption and authentication  
- Automation of builds and deployments using CI/CD  
- Usage of IaC with Kubernetes and Helm  
- Best practices in Jenkins pipelines
- Full documentation cycle  


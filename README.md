


<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <link rel="stylesheet" href="styles.css" />
</head>
<body>
  <p align="center">
    <img 
      src="my-ng-files/IAM & Cloud Security portfolio banner.png" 
      alt="IAM & Cloud Security portfolio banner.png" 
      style="width: 1080px; height: 850px; border-radius: 12px;" 
    />
  </p>
</body>
</html>

Still in progress.....

# Summary

This portfolio showcases my understanding of IAM & Cloud Security, managing user access effectively and protecting cloud environments. Identity and Access Management (IAM) ensures that the right individuals have secure access to the appropriate resources, using tools like multi-factor authentication, role-based access control, and user policies. Cloud Security involves implementing measures such as encryption, firewalls, and monitoring to safeguard data and resources in the cloud. Together, they form the foundation for secure, compliant, and efficient cloud operations.

---

# Cloud Security & IAM Overview

Cloud Security encompasses the strategies, policies, and technologies used to protect cloud-based systems, data, and infrastructure from cyber threats. It involves measures such as encryption, intrusion detection systems, security groups, and continuous monitoring to ensure the confidentiality, integrity, and availability of cloud resources.

Identity and Access Management (IAM) is a critical component of cloud security that manages user identities and controls access to cloud resources. It involves creating and managing user accounts, setting permissions, and implementing authentication mechanisms like multi-factor authentication (MFA) to ensure that only authorized individuals can access specific data and services.

**Key Components:**

**Encryption:** Protects data at rest and in transit.
**Access Controls:** Define who can access what and under which conditions.
**Monitoring & Auditing:** Track activities for suspicious behavior and compliance.
**Multi-Factor Authentication (MFA):** Adds an extra layer of security for user verification.
**Role-Based Access Control (RBAC):** Assigns permissions based on user roles.

**Importance:**
Cloud Security & IAM are vital for safeguarding sensitive information, maintaining regulatory compliance, and ensuring operational resilience in cloud environments.:

**Cloud Security Domains**
---

## Domain 1: Cloud Concepts, Architecture, and Design ![Badge](https://img.shields.io/badge/Cloud%20Concepts-Architecture-brightblue?style=for-the-badge&logo=cloud)

This domain covers the foundational principles of cloud computing security, including deployment models (public, private, hybrid) and service models (IaaS, PaaS, SaaS). It emphasizes designing secure, scalable, and resilient cloud architectures that incorporate best practices such as network segmentation, secure multi-tenancy, and disaster recovery planning. Participants evaluate reference architectures and security design patterns to embed security controls into cloud solutions from the start, ensuring protection against threats and vulnerabilities.

### **IAM Best Practice**
Design secure, scalable identity architectures with strong access controls.
Implementation: Use Azure AD, AWS IAM, or Google Cloud IAM to establish role-based access control (RBAC) and identity federation from the start, embedding identity security into cloud architecture, enabling least privilege, and implementing network segmentation for secure multi-tenancy.

### Relevant Projects:
**IAM-Cross-Account-Access**
  - Manages cross-account IAM permissions for secure multi-account architectures.
**vpc-infrastructure-as-code**
  - Automates secure network design using Infrastructure as Code.
**centralized-logging**
  - Implements centralized log management for architecture monitoring.
**break-glass-access**
  - Emergency access procedures for resilience and security.

---

## Domain 2: Cloud Data Security ![Badge](https://img.shields.io/badge/Data%20Security-Protection-blue?style=for-the-badge&logo=security)

Focuses on securing data in cloud environments throughout its lifecycle—at rest, in transit, and during processing. Techniques include cloud-specific encryption solutions (e.g., AWS KMS, Azure Key Vault), data masking, tokenization, and access control policies using cloud IAM. The domain also covers implementing Data Loss Prevention (DLP) tools integrated with cloud services, data classification frameworks, and privacy compliance (GDPR, HIPAA) to ensure proper data governance and protection in cloud platforms.

### **IAM Best Practice**
Secure infrastructure components with granular identity and access controls.
Implementation: Deploy Azure AD, AWS IAM, or Google Cloud IAM to control access to cloud resources such as VMs, containers, and networking. Use identity federation (e.g., AWS Cognito, Azure AD) and Infrastructure-as-Code (IaC) security practices to enforce access policies and automate vulnerability management with tools like AWS Security Hub or Azure Security Center.

### Relevant Projects:
**Secrets-Management**
  - Manages secrets and encryption keys securely.
**cloud-security-audit**
  - Audits data security controls and compliance.
**cicd-security-pipeline**
  - Secures deployment pipelines involving data and secrets.

---

## Domain 3: Cloud Platform and Infrastructure Security ![Badge](https://img.shields.io/badge/Platform%20&%20Infra-Security-orange?style=for-the-badge&logo=shield)

Centers on securing cloud infrastructure components such as virtual machines, containers, serverless functions, and networking. Participants learn to implement cloud-native security controls like firewalls, security groups, and identity federation (e.g., AWS Cognito, Azure AD). The focus includes securing infrastructure-as-code (IaC) templates, managing vulnerabilities through automated patching, and employing cloud-specific threat detection tools like AWS GuardDuty, Azure Security Center, and Google Cloud Security Command Center to monitor for threats and vulnerabilities.

### **IAM Best Practice**
Secure infrastructure components with granular identity and access controls.
Implementation: Deploy Azure AD, AWS IAM, or Google Cloud IAM to control access to cloud resources such as VMs, containers, and networking. Use identity federation (e.g., AWS Cognito, Azure AD) and Infrastructure-as-Code (IaC) security practices to enforce access policies and automate vulnerability management with tools like AWS Security Hub or Azure Security Center.

### Relevant Projects:
**VPC-Infrastructure-As-Code**
  - Infrastructure security automation.
**cicd-security-pipeline**
  - Secure CI/CD pipeline implementation.
**threat-modeling**
  - Identifies threats in cloud infrastructure.
**cloud-security-audit**
  - Infrastructure security assessments.
**centralized-logging**
  - Monitoring infrastructure threats.

---

## Domain 4: Cloud Application Security ![Badge](https://img.shields.io/badge/Application-Dev-red?style=for-the-badge&logo=code)

Addresses securing cloud-native applications throughout their development lifecycle. Topics include secure coding practices, static and dynamic application security testing (SAST/DAST), and integrating security into CI/CD pipelines using tools like Jenkins, Azure DevOps, or GitLab. The domain emphasizes protecting APIs and microservices via OAuth, API gateways, and IAM policies, as well as defending against common cloud application threats such as injection, XSS, and insecure configurations.

### **IAM Best Practice**
Protect APIs and applications with strong authentication and authorization.
Implementation: Implement OAuth 2.0, OpenID Connect, and API gateways (e.g., Azure API Management, AWS API Gateway) integrated with Okta or Auth0 for secure API access. Apply role-based access policies and enforce secure coding practices, including SAST/DAST tools, to prevent common vulnerabilities.

### Relevant Projects:
**CI/CD-Security-Pipeline**
  - Security in CI/CD pipelines.
**threat-modeling**
  - Application threat detection.
**secrets-management**
  - Protects API keys and secrets.
**cloud-security-audit**
  - Application security assessments.

---

## Domain 5: Cloud Security Operations ![Badge](https://img.shields.io/badge/Operations-Monitoring-yellow?style=for-the-badge&logo=eye)

Focuses on continuous security monitoring and incident response tailored for cloud environments. Participants implement and manage cloud-native SIEM solutions like Azure Sentinel, AWS Security Hub, or Google Chronicle, alongside IDS/IPS tools like Snort or Suricata. They learn to configure cloud monitoring services (AWS CloudWatch, Azure Monitor, Google Cloud Operations Suite), set up automated alerting, and utilize threat intelligence feeds and SOAR platforms to detect, analyze, and respond to security incidents efficiently. Emphasis is placed on maintaining operational resilience and automating response workflows in a dynamic cloud landscape.

### **IAM Best Practice**
Enable continuous monitoring of access and user activity.
Implementation: Use Azure Sentinel, AWS Security Hub, or Google Chronicle combined with CloudTrail, Azure Monitor, or Google Cloud Operations to track access logs. Configure alerts for suspicious activity, integrate with SOAR platforms, and enforce automated incident response workflows, ensuring proper access oversight.

### Relevant Projects:
**Centralized-Logging**
  - Centralized logs for monitoring.
**cloud-security-audit**
  - Security audits.
**break-glass-access**
  - Emergency access procedures.
**threat-modeling**
  - Threat detection and response.

---

## Domain 6: Legal, Risk, and Compliance![Badge](https://img.shields.io/badge/Legal-Risk-green?style=for-the-badge&logo=gavel)

Covers the regulatory frameworks governing cloud security, such as GDPR, HIPAA, PCI DSS, ISO/IEC 27001, and FedRAMP. It explains the specific security controls, data handling requirements, and audit procedures mandated by each regulation. Participants learn to perform risk assessments aligned with NIST SP 800-30, conduct cloud-specific audits, and develop compliance strategies that incorporate cloud security controls. This ensures organizations meet legal obligations, protect sensitive data, and maintain audit readiness in cloud environments.

### **IAM Best Practice**
Ensure access controls and identity policies support regulatory compliance.
Implementation: Leverage tools like Saviynt, SailPoint, or CyberArk to automate access reviews, enforce policies aligned with standards like GDPR, HIPAA, and PCI DSS, and maintain audit trails. Conduct risk assessments and compliance audits regularly to verify that IAM controls meet legal and regulatory requirements.

### Relevant Projects:
**Cloud-Security-Audit**
  - Auditing for compliance.
**secrets-management**
  - Secrets management for compliance.
**threat-modeling**
  - Risk assessment and mitigation.

---

### **Identity and Access Management (IAM)**

**Identity and Access Management (IAM)** is a fundamental aspect of cloud security that involves managing digital identities and controlling access to cloud resources. It ensures that only authorized users and systems can perform specific actions, thereby safeguarding sensitive data and infrastructure.

**Core Components:**
IAAA Framework
- **Identification:** The process where a user or system claims an identity (e.g., username, ID number) to begin access. 
- **Authentication:** Verifies a user's identity, answering "Who are you?" using credentials like passwords, biometrics, or MFA. 
- **Authorization:** Determines what an authenticated user can access and what actions they can perform, answering "What can you do?" 
- **Auditing & Reporting:** Tracks and logs all user access and activity to ensure accountability and compliance.
  
**5th pillar in the IAM model:**
- **Administration:** Manages user identities, roles, and permissions throughout their lifecycle (onboarding, changes, offboarding). 

**Core Features of IAM:**
- **Identity Governance & Administration (IGA):** The overall framework for managing identities and access policies.
- **User Provisioning and De-provisioning:** User provisioning and de-provisioning automate the JML cycle by granting access to Joiners, updating it for Movers, and revoking it for Leavers to maintain security.
- **User Identity Management:** Creating, updating, and deleting user accounts.
- **Access Reviews (or Access Certifications):** Serve as a critical audit mechanism to verify that user provisioning remains accurate and that de-provisioning has been fully executed.
- **Role-Based Access Control (RBAC):** Simplifies permission management by assigning predefined roles to users based on their responsibilities.
- **Privileged Access Management (PAM):** Focuses on securing high-risk, privileged accounts. 
- **Policy Management:** Defining security policies that govern access rules and conditions.

**Best Practices:**
- Implement multi-factor authentication (MFA) for all users.
- Follow the principle of least privilege—grant only necessary permissions.
- Regularly review and audit access logs and permissions.
- Use roles and groups to streamline permission management.

**Benefits:**
- Enhanced security by controlling access tightly
- Simplified user management
- Improved compliance with regulatory standards
- Reduced risk of insider threats and data breaches

---

## 🛡️ Zero Trust Architecture (ZTA)

### Overview
This section demonstrates the design and implementation of **Zero Trust Architecture (ZTA)** as a foundational security model across identity, cloud, and data environments. Zero Trust replaces perimeter-based trust with **continuous verification**, enforcing least privilege and context-aware access decisions at every layer.

The focus is on translating Zero Trust principles into **practical, auditable, and scalable enterprise controls** aligned with governance and compliance requirements.

---

### **Core Zero Trust Principles**
- Never trust, always verify  
- Least privilege access  
- Continuous authentication and authorization  
- Assume breach and limit blast radius  
- Explicit, policy-driven access decisions  

---

### ZTA Domains Implemented

### **Identity & Access**
- Identity as the primary security perimeter  
- Conditional and risk-based access policies  
- Multi-Factor Authentication (MFA) and passwordless access  
- Privileged Access Management (PAM) and Just-In-Time (JIT) access  

### **Cloud & Application Security**
- Secure access to cloud workloads and SaaS applications  
- Identity-aware access to APIs and services  
- Workload identity and service-to-service authentication  
- Role-based and attribute-based access controls  

### **Endpoint & Device Trust**
- Device posture and compliance evaluation  
- Integration with endpoint and MDM solutions  
- Continuous validation of endpoint health  

### **Data Protection**
- Context-aware access to sensitive data  
- Encryption and data classification  
- Data Loss Prevention (DLP) enforcement  

---

### Tools & Technologies

### **Identity & IAM**
- Azure AD / Entra ID  
- AWS IAM  
- Okta  
- Ping Identity  

### **Zero Trust Enforcement**
- Microsoft Conditional Access  
- Zscaler / Prisma Access  
- CyberArk / BeyondTrust (PAM)  

### **Cloud Security**
- AWS (IAM, SCPs, Security Hub)  
- Azure (RBAC, PIM, Defender for Cloud)  

### **Endpoint Security**
- Microsoft Intune  
- Endpoint Detection & Response (EDR) tools  

### **Data Security**
- Microsoft Purview  
- DLP and Information Protection solutions  

---

## 🔍 Access Reviews & Certification

### **Overview**
This section demonstrates the design and execution of **Access Reviews and Access Certification** as a core identity governance capability. The objective is to ensure that user access remains **appropriate, justified, and compliant** throughout the identity lifecycle.

Access reviews are implemented as **periodic, risk-based, and event-driven controls**, supporting least privilege, Zero Trust principles, and regulatory compliance.

---

### **Access Review Principles**
- Access must be periodically validated by accountable owners  
- High-risk access requires more frequent review  
- Certification decisions must be traceable and auditable  
- Automation is preferred over manual review processes  
- Access reviews complement JML and Zero Trust controls  

---

### **Types of Access Reviews Implemented**

### **User Access Reviews**
- Validation of user access to applications, systems, and data  
- Reviewer accountability (manager or application owner)  
- Identification of excessive or outdated access  

### **Privileged Access Reviews**
- Periodic review of elevated and administrative access  
- Validation of business justification  
- Enforcement of least privilege and time-bound access  

### **Role & Entitlement Reviews**
- Review of RBAC role definitions and entitlement mappings  
- Detection of role creep and over-permissioned roles  

### **Event-Driven Reviews**
- Triggered by role changes, department moves, or high-risk events  
- Supports continuous governance and Zero Trust monitoring  

---

### **Access Certification Workflow**

### **Trigger**
- Scheduled review cycle or risk-based event

### **Review Process**
- Access inventory generated automatically  
- Reviewers certify, revoke, or escalate access  
- Decisions recorded with justification  

### **Enforcement**
- Revoked access removed automatically  
- Certification outcomes logged and retained  

---

### **Tools & Technologies**

**Identity & Access Governance**
- Azure AD / Entra ID Access Reviews  
- Active Directory    

### **Access Models**
- Role-Based Access Control (RBAC)  
- Attribute-Based Access Control (ABAC)  

### **Audit & Evidence**
- CSV and JSON access review reports  
- Markdown-based certification records

### **Automation & Reporting**
- PowerShell  
- Python

### **Access Review Automation**

<pre><code>
If ($Review.Cycle -eq "Quarterly") {

    Get-UserEntitlements
    Send-ReviewRequest
    Capture-ReviewerDecision

    If ($Decision -eq "Revoke") {
        Remove-RoleAccess
        Revoke-PrivilegedAccess
    }

    Log-AccessReviewEvidence
}
  </code></pre>

### **Access Certification Automation**

<pre><code>
  If ($Certification.Status -eq "Pending") {

    Notify-Certifier
    Await-Attestation

    If ($Certification.Decision -eq "Denied") {
        Disable-Identity
        Remove-RoleAccess
        Invalidate-Sessions
    }

    Archive-CertificationEvidence
}
  </code></pre>
  
---

### **Governance & Compliance Alignment**
Access reviews and certification activities align with:

- **NIST SP 800-53** (AC-2, AC-3, AC-6, IA-2)  
- **ISO/IEC 27001** (A.9 Access Control)  
- **SOC 2 Trust Services Criteria**  
- **SOX, HIPAA, PCI-DSS** (where applicable)  

These controls support **periodic access validation, segregation of duties, and audit readiness**.

---

### **Outcomes**
- Reduced excessive and dormant access  
- Improved accountability for access decisions  
- Stronger compliance posture  
- Early detection of access risk  
- Clear audit trails and certification evidence  

---

### **Why Access Certification Matters**
Access reviews and certification ensure that access is not only **granted correctly**, but **remains appropriate over time**, closing the governance gap left by provisioning and deprovisioning alone.

---

### **Governance & Compliance Alignment**
Zero Trust implementations in this portfolio align with:

- **NIST SP 800-207 (Zero Trust Architecture)**  
- **NIST SP 800-53** (AC, IA, SC, CM control families)  
- **ISO/IEC 27001**  
- **SOC 2 Trust Services Criteria**  

This demonstrates how Zero Trust supports **audit readiness, risk reduction, and regulatory compliance** in enterprise environments.

---

### **Outcomes**
- Reduced attack surface and lateral movement  
- Improved visibility into access and data usage  
- Stronger compliance posture  
- Scalable security for cloud-first organizations  
- Clear linkage between technical controls and business risk

---

## 🔄 Identity Lifecycle Management (Joiner Mover Leaver)

### **Overview**
This section demonstrates **automated Identity Lifecycle Management (JML)**, covering **Joiner, Mover, and Leaver** processes as a core IAM capability. The focus is on **secure, policy-driven, and auditable provisioning and deprovisioning**, aligned with Zero Trust principles and enterprise governance requirements.

The implementation emphasizes **pre-provisioning (future-state access)**, automation, and access lifecycle controls that reduce risk, improve operational efficiency, and support regulatory compliance.

---

### Identity Lifecycle Principles
- Identity as the authoritative security control  
- Least privilege access at every lifecycle stage  
- Automation over manual provisioning  
- Pre-provisioning for Day-1 readiness  
- Immediate deprovisioning to reduce insider risk  
- Full auditability and evidence generation  

---

### **JML Lifecycle Stages Implemented**

### **Joiner (Pre-Provisioning)**
- Triggered by authoritative HR events (future hires)  
- Identity created in a disabled state prior to the start date  
- Role-based access assignments applied automatically  
- Accounts enabled on Day-1 without manual intervention  
- Provisioning actions logged for audit purposes  

### **Mover**
- Triggered by role, department, or location changes  
- Automated removal of previous entitlements  
- Assignment of new role-based access  
- Access delta tracking (before/after changes)  
- Periodic access review support  

### **Leaver**
- Triggered by termination or separation events  
- Immediate account disablement  
- Automated access removal across systems  
- Preservation of logs and evidence  
- Support for retention and forensic review   

### **Automation & Reporting**
- PowerShell  
- Python

### **Automated Provisioning Logic**

<pre><code>
If ($User.StartDate -gt (Get-Date)) {
    Create-Identity -Disabled
    Assign-RoleAccess
    Log-ProvisioningEvent
}
</code></pre>

### **Automated De-Provisioning Logic**

<pre><code>
If ($User.Status -eq "Terminated") {
    Disable-Identity
    Remove-RoleAccess
    Revoke-PrivilegedAccess
    Invalidate-Sessions
    Log-DeprovisioningEvent
}
</code></pre>

---

### 🤖 Automation & Orchestration

### **Overview**
This portfolio emphasizes **automation-first Identity Lifecycle Management**, eliminating manual provisioning and ensuring access changes are **consistent, repeatable, and auditable**. Automation is used to enforce policy, reduce human error, and support Zero Trust principles across the Joiner–Mover–Leaver (JML) lifecycle.

All identity actions are triggered by **authoritative business events**, not ad-hoc requests.

---

### **Automation Objectives**
- Eliminate manual access provisioning
- Enforce least privilege by default
- Enable pre-provisioning for future hires
- Ensure immediate deprovisioning for leavers
- Generate audit-ready evidence automatically
- Scale identity governance without increasing operational risk

---

### **Automation Architecture**

Authoritative Source (HR)
        ↓
Rule Engine (RBAC / ABAC)
        ↓
Approval Logic (Optional)
        ↓
Provisioning Scripts
        ↓
Target Systems
        ↓
Logging & Audit Evidence

---

### **Authoritative Identity Source**
- HR data (CSV / JSON simulation)  

### **Access Management**
- Role-Based Access Control (RBAC)  
- Attribute-Based Access Control (ABAC)  

### **Logging & Audit**
- JSON and CSV logs  
- Markdown-based audit evidence  

---

### **Governance & Compliance Alignment**
JML processes in this portfolio are aligned with:

- **NIST SP 800-53** (AC, IA, CM, PS control families)  
- **ISO/IEC 27001** (A.5, A.6, A.8, A.9)  
- **SOC 2 Trust Services Criteria**  
- **SOX / HIPAA / PCI-DSS** (where applicable)  

This alignment demonstrates how automated identity lifecycle management directly supports **audit readiness, control effectiveness, and regulatory compliance**.

---

### **Outcomes**
- Reduced onboarding and offboarding risk  
- Faster Day-1 productivity through pre-provisioning  
- Elimination of orphaned and excessive access  
- Improved audit evidence and traceability  
- Scalable identity governance across environments  

---

### **Why Identity Lifecycle Automation Matters**
Automated JML processes ensure that access is **granted, modified, and revoked** in alignment with business events, reducing human error while enforcing governance and Zero Trust principles across the enterprise.

---


## **Okta Labs** 

## **User Management and Role Assignment**
In this lab, we explored the process of creating and managing user accounts within the Okta Admin Console. We began by adding new users, then assigned the Super Admin role to elevate their permissions. The steps included selecting users, assigning roles, and saving changes to ensure proper access control. This hands-on experience demonstrated how to effectively manage user privileges and maintain security within the Okta identity management platform.

---

Creating Users in the Admin Console
---
1) Select Add Person
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/Add_Users.png)

Assigning Super Admin Role to a User
---
2) Select Admin
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/administrator_assignment_by_admin.png)

Assigning Super Admin Role to a User cont...
---
3) Select Role
---
Next

5) Save Changes
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/administrator_assignment_by_admin_2.png)
---
Last

6) User Elevated to Super Admin
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/administrator_assignment_by_admin_3.png)

## **Configure Group Membership Rules**
In this lab, participants learned how to automate user group management within an identity platform by configuring dynamic group membership rules. The exercise involved creating rules based on user attributes, such as job title or department, to automatically assign users to specific groups. This process streamlines access management, reduces manual administrative effort, and ensures consistent application of security policies. Through hands-on practice, participants gained experience in customizing rules to enforce organizational access controls effectively.

---

Creating Group Membership Rules
---
1) Add people
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_group_membership_rules.png)

2) Change Title to Manager
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_group_membership_rules2.png)

3) Go to Groups, then add Rules
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_group_membership_rules3.png)

4) Add Rule
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_group_membership_rules4.png)

## **Configure Salesforce application with SAML in Okta Admin Portal**
In this lab, participants learned how to set up Single Sign-On (SSO) for Salesforce using SAML 2.0 within the Okta Admin Portal. The process involved integrating Salesforce as a SAML application, configuring the sign-on options, and customizing the user identification format with expression language. Participants also configured Salesforce’s Single Sign-On settings, including issuer, identity provider certificate, and login URLs. This hands-on exercise demonstrated how to establish a secure and seamless authentication experience for users, enabling centralized access control and improved security through SAML-based federation.

---

   How to Configure SAML 2.0 for Salesforce: https://saml-doc.okta.com/SAML_Docs/How-to-Configure-SAML-2.0-in-Salesforce.html
   
---

1) Go to Applications, then click on Browse App Integration Catalog and search Salesforce
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_application_with_SAML_in_okta_admin_portal.png)

2) Click on Salesforce to get to General Settings, then click next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_application_with_SAML_in_okta_admin_portal2.png)

3) At the Sign-On Options tab, select SAML 2.0 and for Application username format, select Custom
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_application_with_SAML_in_okta_admin_portal3.png)

4) Note the Expression Language Reference, then click Done
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_application_with_SAML_in_okta_admin_portal4.png)

5) Navigate to Single Sign-on Settings in Salesforce
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_SSO_settings_in_salesforce_portal.png)

6) Click New for SAML Single Sign-On Settings and fill in the required fields(Issuer, Identity Provider Certificate, Identity Provider Login URL, Custom Logout URL, and Entity ID)
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_SSO_settings_in_salesforce_portal2.png)

7) Click save and check settings
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_SSO_settings_in_salesforce_portal3.png)

## **Configure SP-Initiated SAML between Salesforce and Okta**
In this lab, participants learned how to set up Service Provider (SP)-initiated SAML authentication to enable seamless single sign-on between Salesforce and Okta. The exercise involved configuring domain management within Salesforce, ensuring that the custom domain is available and properly set up for federated login. This configuration allows users to access Salesforce through Okta’s SSO portal, providing a unified and secure authentication experience. The hands-on process demonstrated how to establish a trust relationship between Salesforce and Okta, ensuring secure, streamlined access to organizational resources.

---

1) Search for Domain Management in Quick Search
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_SP-Initiated_SAML_between_salesforce_and_okta.png)

2) Click edit for My Domain Details and check domain availability, then click save
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_SP-Initiated_SAML_between_salesforce_and_okta2.png)

3) Deploy New Domain (oktafundamentals7-dev-ed)
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_SP-Initiated_SAML_between_salesforce_and_okta4.png)

4) Copy the Domain Name, then paste it into the browser
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_SP-Initiated_SAML_between_salesforce_and_okta3.png)

5) Single Sign-on into Salesforce
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_SP-Initiated_SAML_between_salesforce_and_okta4.png)

## **Configure Salesforce Provisioning in Okta**
In this lab, participants learned how to enable and configure provisioning between Okta and Salesforce to automate user lifecycle management. The exercise involved setting up provisioning settings within the Salesforce application in Okta, including enabling user creation, updates, and deactivation. Participants explored how to synchronize user data, assign appropriate roles, and manage user access dynamically. This process enhances operational efficiency, ensures accurate and consistent user information, and maintains security by automating account provisioning and deprovisioning across the integrated systems.

---

Okta Labs Guide: https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/okta_labs.pdf

---

1) Go to Salesforce and switch to Lightning Experience view and search for App Manager
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_provisioning_in_okta.png)

2) Click on New External Client App
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_provisioning_in_okta2.png)

4) Fill Basic Information
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_provisioning_in_okta3.png)

5) Copy Consumer Details
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_provisioning_in_okta4.png)

6) Log ack into Okta and enable API integration. Enter the OAuth Consumer Key and the OAuth Consumer Secret, click Authenticate with Salesforce.com, then click Save.
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_provisioning_in_okta6.png)

7) Integration complete
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_salesforce_provisioning_in_okta7.png)

## **LCM: Configure Salesforce for Life Cycle Management**
In this lab, participants learned how to implement and manage the entire user lifecycle in Salesforce using Okta’s lifecycle management capabilities. The exercise involved configuring automated workflows for user onboarding, updates, and offboarding to ensure that user access is consistently aligned with their current role and status. Participants set up policies for automatic account provisioning, deactivation, and synchronization, enabling secure and efficient management of Salesforce user accounts throughout their employment lifecycle. This process helps organizations reduce manual effort, minimize security risks, and ensure compliance through automated lifecycle workflows.

1) Click edit, then enable Create Users, Update User Attributes, and Deactivate Users
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management.png)

2) Assign Users
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management2.png)

3) User Created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management4.png)

5) Go back to Salesforce and click on Manage Users and search for the user account created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management3.png)

6) LCM: Looking at System Logs and checking for errors
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management5.png)

7) LCM: Deprovision Salesforce Users/ Click x sign next to the user's name to Unassign User
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management6.png)

8) Lastly, view the logs to verify deprovisioning for Fisto Asajj
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management7.png)

9) User is no longer active in Salesforce
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/LCM_configure_salesforce_for_life_cycle_management8.png)

---

## **Multi-Factor Authentication (MFA) Policy**
In this lab, participants learned how to create and manage MFA policies to enhance the security of user authentication. The exercise involved configuring MFA requirements within an identity management platform, including selecting authentication factors such as SMS, authenticator apps, or hardware tokens. Participants set policies based on user roles, locations, or risk levels to enforce multi-factor authentication for sensitive applications and access scenarios. This process helps organizations strengthen security, reduce the risk of compromised credentials, and ensure compliance with security standards.

1) Create Network Policy. Click on the Security tab, then Network, click on the dropdown "Add Zone", then choose IP Zone
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication.png)

2) Add Zone name, Gateway IPs, then click Save
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication3.png)

3) Next, add Dynamic Zone. Fill in the Zone name and Locations. Then click Save
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication4.png)

4) Corporate Locations and Corporate Office are Active
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication5.png)

5) Add another Dynamic Zone for Blocklisted. Fill in the Zone name and Locations. Then click Save
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication6.png)

6) Blocklisted Countries is now Active
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication7.png)

7) Set Password Policy. Click on Authenticator
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication8.png)

8) Add Okta Verify
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication9.png)

9) Go to Password Policy, click on Action, then Edit. Add New Password Policy
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication10.png)

10) Add Policy name, Policy description, Add group, and Password age
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication11.png)

11) Add Policy name, Policy description, Add group, Password, then Create Policy age cont..
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication12.png)

12) Next, select Rule name, User's IP is, and Recovery authenticators, then Create Rule
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication13.png)

13) Sales-Okta Password Policy is now Active
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication14.png)

14) Sales-Okta Password Policy is now Active cont...
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/multi_factor_authentication15.png)

---

## **Global Authentication Policy in Action**
In this lab, participants explored how to implement and enforce a comprehensive authentication policy across an organization. The exercise involved configuring global policies that specify authentication requirements, such as multi-factor authentication (MFA), adaptive risk-based authentication, and password policies. Participants observed how these policies apply universally to all users and applications, ensuring consistent security standards. The session demonstrated how to monitor policy enforcement and adjust settings as needed to balance security with user convenience, thereby strengthening overall organizational security posture.

1) Navigate to Global Authentication Policy
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/global_authentication_policy.png)

2) Click Add Policy. Fill Policy name, Policy description, and Assign to groups. Then click Create Policy and Add Rule
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/global_authentication_policy2.png)

3) Corporate Policy Rule created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/global_authentication_policy3.png)

---

## **Microsoft Identity and Access Labs**

### 🚀 Lab 1: Configure and manage built-in and custom Microsoft Entra roles
This lab guides you through configuring and managing Microsoft Entra (Azure AD) roles, including assigning built-in roles to users and creating custom roles tailored to specific administrative needs. You will learn how to assign roles securely, understand role scopes, and customize roles to implement the principle of least privilege effectively in your environment.

1) Add a new Custom Role. Add Name, then click next twice, then create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built_in.png).

2) Add permission to Custom Role. Then click next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built_in2.png).

3) Click Create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built_in3.png).

4) Custom Role Created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built_in4.png).

---
### 🔑 Lab 2: Setting up a domain controller

1) Click Manage, then Add Roles and Features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller.png).

2) Choose Role-based or feature-based installation
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller2.png).

3) Select a server from the server pool
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller3.png).

4) Click next, then Add Features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller4.png).

5) Features installing
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller5.png).

6) Click on Promote this server to a domain
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller6.png).

7) Deployment Configuration, click Next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller7.png).

8) Fill out Domain Controller Options, then click next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller9.png).

9) Enter the NetBIOS Domain name, then click Next twice
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller10.png).

10) Verify Prerequisites(Check and fix prerequisites errors before proceeding)
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller11.png).

11) AD Domain Controller Installed 
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/setting_up_a_domain_controller12.png).

### 🔑 Lab 3: Configure and manage built-in and custom Microsoft Entra roles
This lab walks you through the process of configuring and managing Microsoft Entra (Azure AD) roles. You will learn how to assign and modify built-in roles to meet organizational needs, as well as create and customize custom roles for specific administrative tasks. This exercise emphasizes the importance of role-based access control (RBAC) to enforce the principle of least privilege and enhance security within your Azure environment.

1) Select New Custom Role
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles.png).

2) Add name, then click next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles2.png).

3) Search user, then select permission, then click next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles3.png).

4) Review + Create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles4.png).

5) Custom Helpdesk User Properties Tier 1 role successfully created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles5.png).
---

### 🔒 Lab 4: Configure and manage administrative units
This lab guides you through the process of configuring and managing Administrative Units within Microsoft Entra (Azure AD). You will learn how to create administrative units to delegate management of specific groups or users, assign roles at the administrative unit level, and enforce scoped administrative permissions. This practice helps in segmenting administrative responsibilities and maintaining a secure, organized management structure in large or complex environments.

1) Create New User
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles.png).

2) Add User principal name, Display name, and password, then click next: properties
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles2.png).

2) Add Info, then click next: assignment
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles3.png).

3) Click Review + Create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles4.png).

4) Click on Administrative Unit, then add Administrative Unit, then Review + Create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_built-in_and_custom_microsoft_entra_roles5.png).

5) Administrative Unit Created Successfully
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_administrative_units6.png).

6) User added to Administrative Unit 
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_administrative_units7.png).

### ✅ Lab 5: Configure and manage domains in Microsoft Entra ID and Microsoft 365
This lab covers the process of configuring and managing custom domains within Microsoft Entra ID (Azure AD) and Microsoft 365. You will learn how to add, verify, and troubleshoot domain ownership, set up domain-specific policies, and manage DNS records. This enables seamless integration of your organization’s branded domains, ensuring consistent identity management across Azure AD and Microsoft 365 services.
***Settings are based on Organizational Needs***

1) Add Domain 
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_domains_in_microsoft_entra_id_and_microsoft_365.png).

2) Enter the domain name, then click Use Domain
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_domains_in_microsoft_entra_id_and_microsoft_3652.png).

3) Now, verify the Domain, then click continue
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_domains_in_microsoft_entra_id_and_microsoft_3653.png).

4) Now, add a record to verify ownership, then click verify
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_domains_in_microsoft_entra_id_and_microsoft_3654.png).

5) Skip adding DNS records for now, then click continue
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_domains_in_microsoft_entra_id_and_microsoft_3655.png).

6) Domain setup is complete. Click Done.
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_and_manage_domains_in_microsoft_entra_id_and_microsoft_3656.png).

### ✅ Lab 6: Assign, classify, and manage users, groups, and app roles for enterprise apps
This lab focuses on managing access to enterprise applications by assigning users, groups, and app roles. You will learn how to classify and organize users and groups, assign role-based permissions to control access, and effectively manage application roles to ensure secure and streamlined access to enterprise apps within your organization.

---
***Settings are based on organizational needs***
---
1) Go to Entra ID, then click Properties, take note of the properties features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings.png).

2) Next, click User, then User settings, and take note of the User settings features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings3.png).

3) Users settings cont.
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings4.png).

4) Next, select Groups, then Settings, then General, and take note of the General features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings6.png).

5) Next, select Expiration, and take note of the Expiration features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings7.png).

6) Next, select Naming Policy, and take note of the Naming Policy features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings8.png).

### ✅ Lab 7: Configure external identity providers, including protocols such as SAML & WS-Fed
This lab guides you through configuring external identity providers (IdPs) in Microsoft Entra ID (Azure AD), including protocols like SAML and WS-Fed. You will learn how to integrate third-party authentication systems, establish trust relationships, and enable seamless single sign-on (SSO) for external users, enhancing interoperability and user experience across organizational boundaries.

1) Go to Entra ID, then click Properties, take note of the properties features
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/configure_tenant_properties_user_settings_group_settings_and_device_settings.png).

### ✅ Lab 8: Create a conditional access policy that blocks high risk Android...
This lab demonstrates the design and implementation of a Conditional Access policy that blocks authentication attempts from high-risk Android devices. Using identity risk signals and device compliance posture, the policy enforces zero-trust access controls by preventing compromised or non-compliant mobile devices from accessing corporate cloud resources. This lab showcases how cloud identity security, device trust, and risk-based access decisions are used to reduce account takeover, malware propagation, and data exfiltration in enterprise environments.

1) Go to Entra ID, Security, Identity Protection, then User Risk Policy
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/use_entra_ID_protection_to_set_user_risk_to_medium.png).

2) Click user risk, medium and above, then click done, enable policy enforcement, then click save *Note: I do not have access to Policy Enforcement Option 
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/use_entra_ID_protection_to_set_user_risk_to_medium2.png).

3) Click Sign-in Risk Policy, medium and above, low and above, click done, then save
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/use_entra_ID_protection_to_set_user_risk_to_medium3.png).


### ✅ Lab 9: Implement Conditional Access policy assignments and controls
This lab demonstrates the implementation of Azure Conditional Access policies to enforce identity-based security controls across cloud applications. The solution applies policy assignments based on user roles, device compliance status, location, and sign-in risk level. Access controls are enforced through multi-factor authentication (MFA), device compliance requirements, and session restrictions, ensuring only trusted users and devices can access corporate cloud resources.

The lab showcases how Conditional Access enables zero-trust access decisions by evaluating real-time identity risk signals and contextual factors. Policies are scoped using precise user, group, application, and platform assignments to enforce least-privilege access while minimizing business disruption. Audit logs and sign-in reports are used to validate policy effectiveness and support security monitoring and compliance requirements.

1) Go to Entra ID, Conditional Access, then create a new policy
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/implement_conditional_access_policy_assignments_and_controls.png).

2) Go to Entra ID, Conditional Access, and fill out the Conditional Access policy details
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/implement_conditional_access_policy_assignments_and_controls2.png).

3) Go to Entra ID, Conditional Access, and fill out the Conditional Access policy details, Enable policy, then create cont...
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/implement_conditional_access_policy_assignments_and_controls3.png).

4) Conditional Access policy created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/implement_conditional_access_policy_assignments_and_controls4.png).

### ✅ Lab 10: Implement and manage authentication, certificate, temp access pass, OATH, & FIDO2
This lab demonstrates the implementation and management of modern, phishing-resistant authentication methods in a cloud identity environment. The solution configures and enforces multiple strong authentication mechanisms, including certificate-based authentication, Temporary Access Pass (TAP) for secure onboarding, OATH hardware/software tokens, and FIDO2 security keys. These methods are integrated into a centralized identity platform and governed by Conditional Access policies to enforce risk-based, zero-trust authentication.

The lab showcases how organizations replace legacy passwords with strong, cryptographic authentication and secure recovery workflows. It also demonstrates how different authentication methods are assigned by user role, device trust level, and risk posture, enabling secure access for administrators, developers, and end users while maintaining operational flexibility. Audit logs and authentication reports are used to validate enforcement and support compliance and security monitoring.

1) Go to Authentication methods
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/implement_and_manage_authentication_certificate_temp_access_pass_OATH_&_FIDO2.png).

2) Observe the Authentication Methods, Primary & Secondary authentication guide
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/implement_and_manage_authentication_certificate_temp_access_pass_OATH_&_FIDO2_2.png).

### ✅ Lab 13: Implementing & Configuring Privileged Identity Management (PIM)
This lab demonstrates the design and implementation of a Privileged Identity Management (PIM) solution to secure administrative access in a cloud identity environment. The solution enforces just-in-time (JIT) privilege elevation, approval-based access workflows, time-bound role assignments, and multi-factor authentication (MFA) for privileged roles. PIM is used to reduce standing administrative privileges and minimize the attack surface associated with highly privileged accounts.

The lab showcases how organizations implement zero-trust privileged access by requiring explicit justification, approval, and time-limited elevation for sensitive roles such as Global Administrator, Security Administrator, and Application Administrator. Audit logs, access reviews, and role activation reports are used to validate enforcement and support compliance, security operations, and governance requirements.

1) Click on All Services, then search for Privilege Identity Management
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management.png).

2) Go to manage, then Microsoft Entra Roles
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management2.png).

3) Go to Roles, then add Assignment, select roles, then user administrator. Click next
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management3.png).

4) At the add Assignment page, click activate
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management4.png).

5) PIV created
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management5.png).

6) Now click Activate
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management6.png).

7) Check the Active assignments tab
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Privilege_Identity_Management7.png).

### ✅ Lab 16: Plan, create, configure, and manage Access Reviews in Entra ID
This lab demonstrates the planning, implementation, and operational management of Access Reviews in Microsoft Entra ID to ensure continuous validation of user access to cloud resources, applications, and privileged roles. The solution enforces periodic access recertification for users, guests, and service principals across critical groups, applications, and Azure role assignments, supporting least-privilege access and regulatory compliance.

The lab showcases how organizations automate access governance by requiring business and security stakeholders to regularly attest to user access needs. Review workflows are configured with approval rules, escalation paths, and automatic remediation actions to remove unauthorized or stale access. Audit logs and review reports are used to validate enforcement and provide evidence for compliance, identity governance, and security operations.

1) Go to Microsoft Entra ID, click on Identity Governance
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID.png).

2) Click on Access Reviews, then New Access
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID2.png).

3) Fill in the new access review details, then click reviews
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID3.png).

4) Fill in the new access review details, then click settings 
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID5.png).

5) Fill in the new access review details, then click settings cont..
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID6.png).

6) Add review name, then create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID7.png).

7) Access review details
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Access_Reviews_in_Entra_ID8.png).


  ### ✅ Lab 17: Configuring notifications
This lab demonstrates the configuration and management of security and identity notifications to provide real-time visibility into authentication events, access changes, and governance actions within a cloud identity environment. The solution implements alerting for high-risk sign-ins, Conditional Access policy enforcement, privileged role activations, Access Review outcomes, and directory changes. Notifications are delivered through email and security operations channels to support rapid incident response and continuous monitoring.

The lab showcases how organizations build proactive identity security operations by integrating notifications into their SOC workflows. Alert rules are scoped by severity, user role, and risk level to reduce alert fatigue while ensuring high-impact events receive immediate attention. Audit logs and alert reports are used to validate notification delivery and support compliance, security operations, and identity governance.

1) Go to Microsoft Entra ID, all services, then search notifications hubs
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Configuring_notifications.png).

2) Go to Microsoft Entra ID, all services, then search notifications hubs
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Configuring_notifications2.png).

3) Fill in notifications hubs details, then click create
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Configuring_notifications3.png).

4) Notification deployed
![Add Users](https://raw.githubusercontent.com/agustus9/Cloud-Security-IAM-Portfolio/main/my-ng-files/Configuring_notifications4.png).

---

## **SailPoint Labs coming soon...**
### ✅ Lab 1:Identity Lifecycle Management (Joiner–Mover–Leaver)
### ✅ Lab 2:Access Certification Campaign Design
### ✅ Lab 3:Role-Based Access Control (RBAC) and Role Engineering
### ✅ Lab 4:Segregation of Duties (SoD) Policy Design
### ✅ Lab 5:Privileged Access Governance Integration
### ✅ Lab 6:Identity Risk Scoring Model
### ✅ Lab 7:Access Request and Approval Workflow

## 🛠️ Third-Party IAM Solutions
- **Okta**: Unified identity management and Single Sign-On (SSO), supporting multi-cloud environments and enterprise integrations.
- **SailPoint**: Built-in identity and access management features within the Salesforce ecosystem, enabling secure user access and federation.
- **CyberArk**: Security solution specializing in privileged access management and safeguarding critical assets.
- **Saviynt**: Identity governance platform for managing access and compliance across hybrid and multi-cloud environments.
- **Ping Identity**: Advanced authentication and access management supporting multi-factor authentication and zero-trust security.
  
---

## 🚀 Best Practices & Technical Considerations

---

### ✅ 1. Use Standards-Based Protocols
- **Adopt protocols like** **SAML**, **OAuth 2.0**, and **OpenID Connect** to ensure interoperability across diverse IAM systems and cloud platforms.

---

### 🔑 2. Maintain a Single Source of Truth
- Centralize user identities within a trusted identity provider to prevent discrepancies and simplify management.

---

### ⚙️ 3. Automate User Provisioning & Deprovisioning
- Utilize **SCIM (System for Cross-domain Identity Management)** or **API integrations** to automate account creation, updates, and revocations based on organizational changes.

---

### 🔐 4. Enforce MFA & Least Privilege
- Mandate **Multi-Factor Authentication (MFA)** for all users to enhance security.
- Follow the **least privilege principle**—grant only permissions necessary for each user's role to minimize risk.

---

### 🔍 5. Regularly Review Policies & Logs
- Conduct periodic audits of **trust policies**, **access logs**, and **permissions**.
- Adjust policies as organizational needs evolve to maintain security and compliance.

---

### 📝 Summary
Implementing these best practices ensures a robust, secure, and manageable IAM environment across your cloud and on-premises infrastructure.



Still in progress.....

class Chatbot:
    def __init__(self):
        self.persona = "Incident Response Assistant designed for a cybersecurity website."
        self.role = "To assist SOC analysts, IT teams, and security engineers during cybersecurity incidents by providing step-by-step guidance, structured playbooks, and best practices."
        self.objectives = [
            "Help users identify, analyze, contain, eradicate, and recover from security incidents.",
            "Ask clarifying questions when incident details are missing.",
            "Provide clear, actionable steps in a logical order.",
            "Avoid panic, speculation, or unsafe advice.",
            "Focus on defensive, ethical, and legal cybersecurity practices only."
        ]
        self.security_rules_deny = [
            "hacking systems", "bypassing authentication", "creating malware",
            "exploiting vulnerabilities", "attack instructions"
        ]
        self.security_rules_affirm = [
            "recommend legal authorization", "encourage logging, evidence preservation, and forensics",
            "suggest escalation to senior IR teams when required"
        ]

        self.clarifying_questions = [
            "What operating system is affected?",
            "Is this a production or test environment?",
            "Are logs available for the affected system?",
            "Is this incident still ongoing, or has it been contained?",
            "Have you received any alerts from SIEM or EDR solutions?"
        ]

        self.playbooks = {
            "ransomware_attack": {
                "name": "Ransomware Attack Response",
                "description": "Guidance for handling active ransomware infections.",
                "time_estimate": "2-4 hours (initial response)",
                "severity": "Critical",
                "color": "red",
                "frameworks": ["NIST", "SANS"],
                "steps": {
                    "identification": [
                        "1. Isolate infected systems immediately (disconnect from network).",
                        "2. Identify the ransomware strain and its characteristics.",
                        "3. Collect samples of encrypted files and ransom notes.",
                        "4. Check endpoint detection and response (EDR) logs for initial access."
                    ],
                    "containment": [
                        "1. Prevent lateral movement by isolating all potentially affected systems.",
                        "2. Block known malicious IPs/domains at firewalls/proxies.",
                        "3. Disable network shares used by the ransomware.",
                        "4. Review and enforce access controls."
                    ],
                    "eradication": [
                        "1. Restore systems from clean, verified backups.",
                        "2. Patch all vulnerabilities that allowed initial compromise.",
                        "3. Force password resets for all potentially exposed accounts.",
                        "4. Remove persistence mechanisms (e.g., scheduled tasks, rogue services)."
                    ],
                    "recovery": [
                        "1. Verify system integrity and functionality.",
                        "2. Monitor systems closely for signs of reinfection.",
                        "3. Implement enhanced security controls (e.g., MFA, application whitelisting).",
                        "4. Bring systems back online in a controlled, phased manner."
                    ],
                    "lessons_learned": [
                        "1. Conduct a thorough root cause analysis.",
                        "2. Update security policies and procedures.",
                        "3. Enhance employee training on phishing and security best practices.",
                        "4. Improve backup and recovery strategies."
                    ]
                }
            },
            "phishing_email": {
                "name": "Phishing Email Investigation",
                "description": "Steps to analyze and respond to suspected phishing emails.",
                "time_estimate": "30-60 minutes",
                "severity": "Medium",
                "color": "yellow",
                "frameworks": ["NIST"],
                "steps": {
                    "identification": [
                        "1. User reports suspicious email to security team.",
                        "2. Analyze email headers for sender reputation and SPF/DKIM/DMARC status.",
                        "3. Safely analyze URLs and attachments (e.g., in a sandbox environment).",
                        "4. Check for similar emails across the organization."
                    ],
                    "containment": [
                        "1. Remove malicious emails from all inboxes.",
                        "2. Block sender domain/IP at email gateway.",
                        "3. If credentials were entered, reset affected user passwords.",
                        "4. Isolate any systems that clicked malicious links or opened attachments."
                    ],
                    "eradication": [
                        "1. Delete all instances of the malicious email.",
                        "2. Clean any infected systems if attachments were malicious.",
                        "3. Ensure all users are aware of the phishing campaign."
                    ],
                    "recovery": [
                        "1. Verify no further compromise occurred (e.g., account activity, data exfiltration).",
                        "2. Reinforce user awareness training on phishing identification.",
                        "3. Monitor for related threats."
                    ],
                    "lessons_learned": [
                        "1. Review effectiveness of email filters.",
                        "2. Update phishing simulation exercises.",
                        "3. Improve incident response procedures for phishing."
                    ]
                }
            },
            "account_compromise": {
                "name": "Account Compromise Response",
                "description": "Response for detecting and mitigating compromised user accounts.",
                "time_estimate": "1-3 hours",
                "severity": "High",
                "color": "orange",
                "frameworks": ["MITRE ATT&CK"],
                "steps": {
                    "identification": [
                        "1. Detect unusual login activity, password reset alerts, or user reports.",
                        "2. Review identity provider logs for suspicious access attempts.",
                        "3. Determine scope: which accounts, when, from where.",
                        "4. Check for unauthorized changes to mailboxes or cloud services."
                    ],
                    "containment": [
                        "1. Immediately disable or suspend the compromised account(s).",
                        "2. Revoke active sessions and enforce MFA for all users.",
                        "3. Block suspicious IPs/geolocations at network perimeter.",
                        "4. Investigate for lateral movement to other accounts or systems."
                    ],
                    "eradication": [
                        "1. Force password reset for the compromised account.",
                        "2. Remove any unauthorized forwarding rules or mailbox delegates.",
                        "3. Remove unauthorized applications or API keys.",
                        "4. Scan affected endpoints for malware."
                    ],
                    "recovery": [
                        "1. Restore legitimate access for the user.",
                        "2. Monitor the account and related activities closely.",
                        "3. Reinforce strong password policies and MFA usage.",
                        "4. Conduct user awareness training."
                    ],
                    "lessons_learned": [
                        "1. Analyze root cause (e.g., weak password, phishing, credential stuffing).",
                        "2. Enhance identity and access management (IAM) controls.",
                        "3. Review detection mechanisms for anomalous logins."
                    ]
                }
            },
            "data_breach": {
                "name": "Data Breach Response",
                "description": "Steps for managing incidents involving unauthorized data exfiltration.",
                "time_estimate": "Days to Weeks",
                "severity": "Critical",
                "color": "purple",
                "frameworks": ["ISO/IEC 27035"],
                "steps": {
                    "identification": [
                        "1. Confirm data exfiltration or unauthorized access to sensitive data.",
                        "2. Identify the type and volume of data affected.",
                        "3. Determine the systems and databases involved.",
                        "4. Identify the timeline and method of compromise."
                    ],
                    "containment": [
                        "1. Isolate compromised systems and networks to prevent further exfiltration.",
                        "2. Block external C2 (Command and Control) channels.",
                        "3. Revoke access to affected data stores.",
                        "4. Preserve forensic evidence immediately."
                    ],
                    "eradication": [
                        "1. Close all identified vulnerabilities that led to the breach.",
                        "2. Remove all unauthorized access points, backdoors, and malware.",
                        "3. Force credential resets for all affected users/systems.",
                        "4. Rebuild compromised systems if necessary."
                    ],
                    "recovery": [
                        "1. Restore data from secure backups.",
                        "2. Verify integrity and confidentiality of data.",
                        "3. Implement enhanced data loss prevention (DLP) controls.",
                        "4. Communicate with affected parties and regulators as required by law."
                    ],
                    "lessons_learned": [
                        "1. Conduct a comprehensive forensic investigation and root cause analysis.",
                        "2. Review and update data handling policies and security architecture.",
                        "3. Implement additional security technologies.",
                        "4. Provide detailed reporting to management and legal counsel."
                    ]
                }
            },
            "ddos_attack": {
                "name": "DDoS Attack Mitigation",
                "description": "Guidance for defending against Distributed Denial of Service attacks.",
                "time_estimate": "Minutes to Hours",
                "severity": "High",
                "color": "blue",
                "frameworks": ["NIST"],
                "steps": {
                    "identification": [
                        "1. Detect unusual traffic spikes, service unavailability, or high resource utilization.",
                        "2. Analyze traffic patterns and source IPs to confirm DDoS signature.",
                        "3. Determine the type of DDoS attack (e.g., volumetric, protocol, application-layer).",
                        "4. Identify affected services and infrastructure components."
                    ],
                    "containment": [
                        "1. Activate DDoS mitigation services (ISP, CDN, dedicated appliance).",
                        "2. Implement rate limiting and traffic filtering rules.",
                        "3. Route traffic through scrubbing centers.",
                        "4. Utilize blackholing or sinkholing for severe cases."
                    ],
                    "eradication": [
                        "1. Work with service providers to block attack sources.",
                        "2. Fine-tune mitigation rules to prevent future attacks.",
                        "3. Hardening network infrastructure against common DDoS vectors."
                    ],
                    "recovery": [
                        "1. Verify service availability and performance post-mitigation.",
                        "2. Monitor network traffic for residual attack activity.",
                        "3. Review and optimize network configurations.",
                        "4. Communicate service restoration to users."
                    ],
                    "lessons_learned": [
                        "1. Analyze attack vectors and mitigation effectiveness.",
                        "2. Update DDoS response plan and playbooks.",
                        "3. Invest in advanced DDoS protection solutions.",
                        "4. Conduct regular DDoS drills."
                    ]
                }
            },
            "malware_detected": { # This is a simpler "malware" entry, distinct from full ransomware playbook
                "name": "Malware Detection Initial Response",
                "description": "Initial steps upon detecting general malware.",
                "time_estimate": "15-30 minutes",
                "severity": "Medium",
                "color": "red",
                "frameworks": ["SANS"],
                "steps": {
                    "identification": [
                        "1. Confirm malware detection via EDR/AV alert or user report.",
                        "2. Identify affected endpoint(s) and user(s).",
                        "3. Collect incident details: malware name, detection time, affected processes."
                    ],
                    "containment": [
                        "1. Isolate the affected endpoint(s) from the network.",
                        "2. Prevent execution of known malware hashes.",
                        "3. Review related security alerts for wider compromise."
                    ],
                    "eradication": [
                        "1. Run full anti-malware scans on isolated systems.",
                        "2. Remove identified malware and associated artifacts.",
                        "3. Patch any exploited vulnerabilities.",
                        "4. Force password reset if credentials might be compromised."
                    ],
                    "recovery": [
                        "1. Restore clean system state if necessary (e.g., from backup/image).",
                        "2. Verify system integrity.",
                        "3. Reconnect to network and monitor closely."
                    ],
                    "lessons_learned": [
                        "1. Analyze malware for indicators of compromise (IOCs) and tactics.",
                        "2. Update detection rules and security awareness training."
                    ]
                }
            }
        }

    def _check_security_rules(self, message):
        message_lower = message.lower()
        for denied_term in self.security_rules_deny:
            if denied_term in message_lower:
                return "I cannot assist with requests related to hacking, exploiting vulnerabilities, or creating malware. My purpose is to provide defensive, ethical, and legal cybersecurity guidance only."
        return None

    def _handle_incident_type(self, incident_type_key):
        # Update to provide a playbook summary if available
        playbook_data = self.playbooks.get(incident_type_key)
        if playbook_data:
            response = f"### {playbook_data['name']} ({playbook_data['severity']} Severity)\n"
            response += f"**Description:** {playbook_data['description']}\n"
            response += f"**Estimated Time:** {playbook_data['time_estimate']}\n"
            response += f"**Relevant Frameworks:** {', '.join(playbook_data['frameworks'])}\n\n"
            response += "To get step-by-step guidance, please ask for a specific stage, e.g., 'identification for ransomware' or 'containment for phishing email'."
            return response

        # Fallback to generic if no specific playbook, though inc_type should match a playbook key here
        guidance = self.incident_types.get(incident_type_key.lower())
        if guidance:
            response = f"### Guidance for {incident_type_key.title()} Incident\n"
            response += guidance + "\n"
            response += "Always begin with **Identification** and proceed through the IR lifecycle: **Containment**, **Eradication**, **Recovery**, and **Lessons Learned**."
            return response
        return None

    def get_response(self, user_message):
        security_check_result = self._check_security_rules(user_message)
        if security_check_result:
            return security_check_result

        security_check_result = self._check_security_rules(user_message)
        if security_check_result:
            return security_check_result

        user_message_lower = user_message.lower()
        response = None # Initialize response
        
        if "hello" in user_message_lower:
            response = f"Hello there! As your {self.persona}, how can I help you with incident response today?"
        elif "incident status" in user_message_lower:
            response = "All systems are operational. No active incidents reported. Remember to focus on proactive monitoring and threat intelligence."
        else:
            # Check for specific playbook stage requests (e.g., "identification for ransomware")
            for pb_key, playbook_data in self.playbooks.items():
                if pb_key.replace('_', ' ') in user_message_lower:
                    # Check for specific stages within the playbook
                    if "identification" in user_message_lower:
                        response = f"### {playbook_data['name']} - Identification\n" + "\n".join(playbook_data['steps']['identification'])
                        break
                    elif "containment" in user_message_lower:
                        response = f"### {playbook_data['name']} - Containment\n" + "\n".join(playbook_data['steps']['containment'])
                        break
                    elif "eradication" in user_message_lower:
                        response = f"### {playbook_data['name']} - Eradication\n" + "\n".join(playbook_data['steps']['eradication'])
                        break
                    elif "recovery" in user_message_lower:
                        response = f"### {playbook_data['name']} - Recovery\n" + "\n".join(playbook_data['steps']['recovery'])
                        break
                    elif "lessons learned" in user_message_lower:
                        response = f"### {playbook_data['name']} - Lessons Learned\n" + "\n".join(playbook_data['steps']['lessons_learned'])
                        break
                    else:
                        # If playbook name is mentioned but no stage, return general playbook summary
                        response = self._handle_incident_type(pb_key)
                        break
            
            if response is None: # If no playbook or specific stage was matched yet
                # Check for general incident types
                for inc_type_key, inc_type_desc in self.incident_types.items():
                    if inc_type_key in user_message_lower:
                        response = self._handle_incident_type(inc_type_key)
                        break

            if response is None: # Only proceed if no incident type or playbook was matched
                if "identification" in user_message_lower or "identify incident" in user_message_lower:
                    response = self._handle_identification()
                elif "containment" in user_message_lower or "contain incident" in user_message_lower:
                    response = self._handle_containment()
                elif "eradication" in user_message_lower or "eradicate incident" in user_message_lower:
                    response = self._handle_eradication()
                elif "recovery" in user_message_lower or "recover systems" in user_message_lower:
                    response = self._handle_recovery()
                elif "lessons learned" in user_message_lower or "post-incident" in user_message_lower:
                    response = self._handle_lessons_learned()
                elif any(keyword in user_message_lower for keyword in ["incident", "help", "assist", "guidance"]):
                    # If a general query about incidents, ask a clarifying question
                    import random
                    response = f"I can help with that. To provide the best guidance, could you tell me: **{random.choice(self.clarifying_questions)}**"
                else:
                    response = (f"You said: {user_message}. I'm still learning, but I can help with basic queries. "
                                f"My role is: {self.role}. Please ask me about incident response topics like 'identification', 'containment', 'eradication', 'recovery', or 'lessons learned', or specific incident types like 'malware' or 'phishing'.")
        
        return response
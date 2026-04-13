<p align="center">
  <!-- Replace with your image -->
  <img src="images/tor-logo.png" alt="TOR Threat Hunt Logo" width="300">
</p>

<h2 align="center">Threat Hunt Report: Detection of Unauthorized TOR Browser Usage</h2>

---

### Scenario Creation

➡️ <a href="tor-activity-simulation.md">View Scenario Creation</a>

---

### Platforms and Technologies Leveraged

- Windows 11 Virtual Machine (Microsoft Azure)  
- Endpoint Detection and Response (EDR): Microsoft Defender for Endpoint  
- Kusto Query Language (KQL)  
- TOR Browser  

---

### Scenario

Unusual encrypted network traffic and connections to known TOR-related ports raised concerns that anonymity tools may be in use on the network. The objective of this threat hunt was to determine whether TOR Browser had been downloaded, installed, and actively used on the endpoint, and to analyze any associated activity.

---

### High-Level TOR IoC Discovery Plan

- Review **DeviceFileEvents** for TOR-related artifacts  
- Analyze **DeviceProcessEvents** for evidence of execution and usage  
- Examine **DeviceNetworkEvents** for outbound connections over TOR-associated ports 

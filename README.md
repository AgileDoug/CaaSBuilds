# CaaSBuilds
ARM and Powershell scripts to build and maintane an Azure CaaS Node (SF+KeyVault+ContainerReg)

This project is essentially focused on builing out consistent CaaS nodes, specifically:
-Service Fabric Cluster w/Containers
   - Load Balancing
        - VMSS
-Key Vault
   - Scripts will build vault and push new cert and vmUserName and vmPassword for SF ARM
-Container Registry - Basic 10gb

Additional scripts and ARM's will come out shortly for the ci/cd management

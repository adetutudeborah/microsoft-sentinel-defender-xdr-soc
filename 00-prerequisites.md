# Prerequisites

- An Azure subscription 
- Owner or Contributor role on the target resource group (needed to create resources and assign RBAC roles during deployment).


# Custom Detection Rules Setup

This step allows your Microsoft Sentinel training lab to automatically create custom detection rules in Microsoft Defender XDR.

**What are custom detection rules?**

Custom detection rules are security instructions that help identify suspicious activity and alert you to potential threats.

To create these rules automatically, the lab needs a **User-Assigned Managed Identity (UAMI)**. Think of this as a special account that allows the automation to access Microsoft Graph and create or manage detection rules.

### Do I need to do this?

- **Yes:** If you want to enable custom detection rules, follow one of the setup methods below.
- **No:** If you want to skip custom detection rules, leave the `detectionRulesIdentityResourceId` field empty during deployment and continue with the rest of the lab.

### Option 1: Automatically set up the identity (recommended)

This method uses a script to create the identity, grant the required permission, verify the setup, and display the identity's resource ID.

1. Open [Azure Cloud Shell](https://portal.azure.com/) in the Azure portal.
2. Select **Bash** as your shell.
3. Run the following commands, replacing `<your-resource-group>` with the name of your Azure resource group.

```bash
curl -fsSLo sentinel-training-lab-onboarding.sh \
  https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Tools/Microsoft-Sentinel-Training-Lab/Tools/sentinel-training-lab-onboarding.sh

bash sentinel-training-lab-onboarding.sh <your-resource-group>
```

The script creates or reuses an identity named `SentinelDetectionRulesIdentity`, assigns the required Microsoft Graph permission (`CustomDetection.ReadWrite.All`), verifies the permission assignment, and prints the full resource ID.

Review the script before running it if you want to understand the commands it executes.

### Option 2: Set up the identity manually

If you prefer not to use the automated script, you can create the identity and assign its permission yourself.

**Step 1: Create the identity**

Open Azure Cloud Shell, select **PowerShell**, and run the following command. Replace `<your-resource-group>` with your resource group name.

```powershell
az identity create --resource-group <your-resource-group> --name SentinelDetectionRulesIdentity
```

This creates the identity that the lab's automation will use.

**Step 2: Grant the required permission**

Run the following commands in the same PowerShell session:

```powershell
$miObjectId = (az identity show --resource-group <your-resource-group> --name SentinelDetectionRulesIdentity --query principalId -o tsv)

$graphSpId = (az ad sp show --id "00000003-0000-0000-c000-000000000000" --query id -o tsv)

$body = @{principalId=$miObjectId; resourceId=$graphSpId; appRoleId="e0fd9c8d-a12e-4cc9-9827-20c8c3cd6fb8"} | ConvertTo-Json -Compress

az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphSpId/appRoleAssignedTo" --headers "Content-Type=application/json" --body $body
```

These commands identify the managed identity and Microsoft Graph, then assign the `CustomDetection.ReadWrite.All` application permission.

You must have sufficient Azure and Microsoft Entra permissions to complete these steps.

### Step 3: Use the identity during deployment

After setup, copy the full resource ID printed by the script, or retrieve it from Azure.

It will look similar to this:

```text
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/SentinelDetectionRulesIdentity
```

In [Onboarding Step 4](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/Microsoft-Sentinel-Training-Lab/Exercises/Onboarding.md#step-4-deploy-the-microsoft-sentinel-training-lab-solution), provide this value for the `detectionRulesIdentityResourceId` deployment parameter.

**Important:** Use your actual subscription ID and resource group name. The example above is only a template.

### Summary

The setup has three main steps:

1. **Create an identity** for the automation.
2. **Grant permission** so it can create and manage custom detection rules.
3. **Provide the identity's resource ID** during deployment so the lab knows which identity to use.

If you do not need custom detection rules, leave the identity field empty and skip this setup.
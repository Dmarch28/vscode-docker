/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.md in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { AzureNameStep, ResourceGroupListStep, resourceGroupNamingRules } from 'vscode-azureextensionui';
import { ext } from '../../../extensionVariables';
import { localize } from '../../../localize';
import { IAciWizardContext } from './IAciWizardContext';

export class ContextNameStep extends AzureNameStep<IAciWizardContext> {
    protected async isRelatedNameAvailable(context: IAciWizardContext, name: string): Promise<boolean> {
        return await ResourceGroupListStep.isNameAvailable(context, name);
    }

    public async prompt(context: IAciWizardContext): Promise<void> {
        context.contextName = await ext.ui.showInputBox({ prompt: localize('vscode-docker.tree.contexts.create.aci.enterContextName', 'Enter context name'), validateInput: validateContextName });

        context.relatedNameTask = this.generateRelatedName(context, context.contextName, resourceGroupNamingRules);
    }

    public shouldPrompt(wizardContext: IAciWizardContext): boolean {
        return !wizardContext.contextName;
    }
}

// Slightly more strict than CLI
const contextNameRegex = /^[a-z0-9][a-z0-9_-]+$/i;
function validateContextName(value: string | undefined): string | undefined {
    if (!contextNameRegex.test(value)) {
        return localize('vscode-docker.tree.contexts.create.aci.contextNameValidation', 'Context names must be start with an alphanumeric character and can only contain alphanumeric characters, underscores, and dashes.');
    } else {
        return undefined;
    }
}

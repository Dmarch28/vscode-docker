/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.md in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { URL } from "url";
import { ociClientId } from "../constants";
import { httpRequest, RequestLike } from './httpRequest';

export function getNextLinkFromHeaders(response: IResponse<unknown>): string | undefined {
    const linkHeader: string | undefined = response.headers.link as string;
    if (linkHeader) {
        const match = linkHeader.match(/<(.*)>; rel="next"/i);
        return match ? match[1] : undefined;
    } else {
        return undefined;
    }
}

export async function registryRequest<T>(node: IRegistryAuthTreeItem | IRepositoryAuthTreeItem, method: 'GET' | 'DELETE' | 'POST', url: string, customOptions?: RequestInit): Promise<IResponse<T>> {
    const options = {
        method: method,
        headers: {
            'X-Meta-Source-Client': ociClientId,
        },
        ...customOptions,
    };

    const baseUrl = options.baseUrl || node.baseUrl || (<IRepositoryAuthTreeItem>node).parent.baseUrl;
    options.baseUrl = undefined;
    let fullUrl: string = url;
    if (!url.startsWith(baseUrl)) {
        let parsed = new URL(url, baseUrl);
        fullUrl = parsed.toString();
    }

    const response = await httpRequest<T>(fullUrl, options, async (request) => {
        if (node.signRequest) {
            return node.signRequest(request);
        } else {
            return (<IRepositoryAuthTreeItem>node).parent?.signRequest(request);
        }
    });

    return {
        body: method !== 'DELETE' ? await response.json() : undefined,
        headers: response.headers,
    };
}

interface IResponse<T> {
    body: T,
    headers: { [key: string]: string | string[] },
}

export interface IRegistryAuthTreeItem {
    signRequest(request: RequestLike): Promise<RequestLike>;
    baseUrl: string;
}

export interface IRepositoryAuthTreeItem extends Partial<IRegistryAuthTreeItem> {
    parent: IRegistryAuthTreeItem;
}

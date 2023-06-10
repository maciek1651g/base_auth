import { AuthenticatorDevice } from '@simplewebauthn/typescript-types';

export interface User {
    email: string;
    password: string;

    secret?: string; // secret for one-time password

    challenge?: any; // temporary for U2F registration and authentication
    authenticator?: AuthenticatorDevice; // public key for U2F
}

export const registeredUsers: User[] = [];
export const sessions = new Map<string, User>();

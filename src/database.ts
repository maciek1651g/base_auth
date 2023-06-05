export interface User {
	email: string;
	password: string;
	secret?: string;
	registrationRequest?: object;
}

export const registeredUsers: User[] = [];
export const logedUsers = new Map<string, User>();

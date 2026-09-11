import type { Authentication, Connection } from "./types.js";

export function authSecretNames(auth: Authentication): string[] {
  switch (auth.type) {
    case "none": return [];
    case "bearer": case "header": case "query": return [auth.secret];
    case "basic": return [auth.usernameSecret, auth.passwordSecret].filter(present);
    case "bindings": return auth.bindings.map(binding => binding.secret);
    case "oauth2": return [auth.clientSecret, auth.refreshSecret].filter(present);
    case "jwt-bearer": return [auth.privateKeySecret];
    case "aws-sigv4": return [auth.accessKeyIdSecret, auth.secretAccessKeySecret, auth.sessionTokenSecret].filter(present);
  }
}

export function connectionSecretNames(connection: Connection): string[] {
  const tls = connection.tls;
  return [...new Set([...authSecretNames(connection.auth), ...(tls ?
    [tls.certificateSecret, tls.privateKeySecret, tls.passphraseSecret].filter(present) : [])])];
}

function present(value: string | undefined): value is string { return value !== undefined; }

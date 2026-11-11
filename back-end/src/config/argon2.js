import argon2 from 'argon2'

// Parâmetros do algoritmo Argon2id para o hash de senhas de usuário
// (recomendação da OWASP para novas aplicações)
export const argon2Options = {
  type: argon2.argon2id,    // Variante Argon2id
  memoryCost: 65 * 1024,    // Memória utilizada: 66560 KiB (65 MiB)
  timeCost: 3,              // Número de iterações
  parallelism: 4            // Grau de paralelismo (threads)
}

// Gera o hash (com sal aleatório embutido) a partir da senha em texto claro
export function hashPassword(password) {
  return argon2.hash(password, argon2Options)
}

// Confere se a senha informada corresponde ao hash armazenado
export async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password ?? '')
  }
  catch(error) {
    // Hash inválido/fora do formato Argon2 (ex.: senha antiga em texto claro)
    return false
  }
}

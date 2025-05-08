// src/shared/recaptcha.ts
import axios from "axios";

export interface RecaptchaResponse {
  success:   boolean;
  score:     number;
  action:    string;
  challenge_ts: string;
  hostname:  string;
  "error-codes"?: string[];
}

export async function verifyRecaptchaToken(token: string): Promise<RecaptchaResponse> {
  const secret = process.env.RECAPTCHA_SECRET_KEY!;
  if (!secret) throw new Error("Falta la variable RECAPTCHA_SECRET_KEY");
  const url = `https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${token}`;
  const { data } = await axios.post<RecaptchaResponse>(url);
  return data;
}

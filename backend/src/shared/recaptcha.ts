import axios from "axios";

export interface RecaptchaResponse {
  success:       boolean;
  score:         number;
  action:        string;
  challenge_ts:  string;
  hostname:      string;
  "error-codes"?: string[];
}

export async function verifyRecaptchaToken(token: string): Promise<RecaptchaResponse> {
  const secret = process.env.RECAPTCHA_SECRET_KEY!;
  if (!secret) throw new Error("Falta la variable RECAPTCHA_SECRET_KEY");

  // Google acepta GET o POST, pero con POST form-data es más confiable:
  const params = new URLSearchParams();
  params.append("secret", secret);
  params.append("response", token);

  const { data } = await axios.post<RecaptchaResponse>(
    "https://www.google.com/recaptcha/api/siteverify",
    params,
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );
  return data;
}

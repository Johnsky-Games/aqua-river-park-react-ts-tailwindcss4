import axios from "axios";

export async function verifyRecaptcha(token: string): Promise<boolean> {
  const secret = process.env.RECAPTCHA_SECRET_KEY!;
  const resp = await axios.post(
    "https://www.google.com/recaptcha/api/siteverify",
    null,
    { params: { secret, response: token } }
  );
  // Google devuelve { success, score, action, ... }
  return resp.data.success && resp.data.score >= 0.5;
}

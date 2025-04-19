export type ServiceType = 'entrada' | 'reserva' | 'evento' | 'vip';

export interface Service {
  id: number;
  title: string;
  description?: string | null;
  price: number;
  duration?: string | null;
  image_url?: string | null;
  type?: ServiceType;
  created_at?: Date;
}

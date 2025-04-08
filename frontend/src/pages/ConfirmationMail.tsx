import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import api from '../api/axios';
import { AxiosError } from 'axios';

const Confirm = () => {
  const { token } = useParams();
  const [message, setMessage] = useState('Confirmando tu cuenta...');
  const [type, setType] = useState<'success' | 'info' | 'error'>('info');

  useEffect(() => {
    const confirmAccount = async () => {
      try {
        await api.get(`/confirm/${token}`);
        setMessage('✅ ¡Tu cuenta ha sido confirmada exitosamente! Ya puedes iniciar sesión.');
        setType('success');
      } catch (err) {
        const error = err as AxiosError<{ message: string }>;

        if (error.response?.data?.message === 'El enlace ya fue utilizado o ha expirado.') {
          setMessage('⚠️ El enlace ya fue utilizado o ha expirado.');
          setType('info');
        } else {
          setMessage('❌ Ocurrió un error al confirmar tu cuenta. Inténtalo nuevamente más tarde.');
          setType('error');
        }
      }
    };

    confirmAccount();
  }, [token]);

  const getColor = () => {
    if (type === 'success') return 'text-green-600';
    if (type === 'error') return 'text-red-500';
    return 'text-yellow-600';
  };

  return (
    <div className="max-w-md mx-auto mt-24 px-6 text-center">
      <h1 className="text-3xl font-bold mb-6">Confirmación de Cuenta</h1>
      <p className={`text-xl font-medium ${getColor()}`}>
        {message}
      </p>

      {type === 'success' && (
        <a
          href="/login"
          className="mt-6 inline-block bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-4 rounded transition"
        >
          Iniciar sesión
        </a>
      )}
    </div>
  );
};

export default Confirm;

// src/components/AutoTokenManager.tsx
import React, { useEffect, useRef } from "react";
import api from "@/api/axios";
import { useAuthStore } from "@/store/useAuthStore";

export const AutoTokenManager: React.FC = () => {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  // inicializo en null para que useRef<number | null> sea válido
  const timeoutRef = useRef<number | null>(null);

  useEffect(() => {
    if (!user) return;

    const scheduleRefresh = () => {
      timeoutRef.current = window.setTimeout(async () => {
        try {
          await api.get("/refresh");
          scheduleRefresh();
        } catch {
          logout();
        }
      }, 14 * 60 * 1000);
    };

    scheduleRefresh();

    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [user, logout]);

  return null;
};

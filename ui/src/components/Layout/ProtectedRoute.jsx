import React, { useEffect, useRef } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import MainLayout from './MainLayout';
import { clearSessionMetadata, authService } from '../../services/api';

const ProtectedRoute = ({ children }) => {
  const tenantId = localStorage.getItem("tenant_id");
  const expiry = parseInt(localStorage.getItem("acp_token_expiry") || "0", 10);
  const isValid = !!tenantId && expiry > Date.now();
  const navigate = useNavigate();
  const verifiedRef = useRef(false);

  useEffect(() => {
    if (!isValid || verifiedRef.current) return;
    verifiedRef.current = true;

    // Server-side token validation — catches revoked/expired cookies the client can't detect
    authService.getMe()
      .then(() => {
        // Session valid
      })
      .catch((err) => {
        if (err.message && err.message.includes("UNAUTHORIZED")) {
          // api.js handles clearSessionMetadata + navigation via authEvents
        }
        // Network error — don't log out, client-side expiry is the fallback
      });
  }, [isValid, navigate]);

  if (!isValid) {
    clearSessionMetadata();
    return <Navigate to="/login" replace />;
  }

  return <MainLayout>{children}</MainLayout>;
};

export default ProtectedRoute;

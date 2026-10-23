# 🔔 HookRelay API — Gateway de Webhooks Confiables con Firma HMAC-SHA256, Circuit Breaker & Dead-Letter Queue

**HookRelay API** es un microservicio **100% Backend** construido en **Node.js 20 + TypeScript 5 + Fastify** bajo **Arquitectura Hexagonal y Event-Driven Outbox**, diseñado para garantizar la entrega confiable de notificaciones Webhook hacia servidores externos sin perder eventos cuando el servidor destino sufre caídas o picos de latencia.

![Node.js 20](https://img.shields.io/badge/Node.js-20_Alpine-339933?logo=nodedotjs&logoColor=white)
![TypeScript 5](https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white)
![Fastify](https://img.shields.io/badge/Fastify-High_Throughput-000000?logo=fastify&logoColor=white)
![Architecture](https://img.shields.io/badge/Architecture-Event--Driven_Outbox_%2B_Hexagonal-8A2BE2)
![Design Patterns](https://img.shields.io/badge/GoF_Patterns-State_(Circuit_Breaker)_%7C_Strategy_%7C_Command-F59E0B)
![Jest](https://img.shields.io/badge/Tests-Jest_Passing-C21325?logo=jest&logoColor=white)

---

## ⚡ Problemas Críticos de Sistemas Distribuidos que Resuelve

1. **Idempotencia Atómica (`Idempotent Receiver Pattern`):**
   - Si el servicio emisor envía dos veces el mismo evento por un *timeout* de red usando la misma `Idempotency-Key`, HookRelay detecta el duplicado en `< 1ms` y devuelve la entrega original sin volver a disparar el Webhook.
2. **Autenticidad Criptográfica Anti-Replay (`HMAC-SHA256` + `timingSafeEqual`):**
   - Firma cada payload con `X-HookRelay-Signature-256: t=<timestamp>,v1=<hmac_sha256>` e incluye un verificador resistente a *Timing Attacks* (`crypto.timingSafeEqual`) con ventana anti-replay de 300 segundos.
3. **Cortacircuitos por Dominio Destino (`State Pattern — Circuit Breaker`):**
   - Cada host destino mantiene su propia máquina de estados (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`). Si un servidor externo falla consecutivamente, el circuito se abre para no saturarlo y realiza sondeos automáticos tras el periodo de enfriamiento.
4. **Reintentos Inteligentes (`Strategy Pattern — Exponential Backoff + Full Jitter`) y `Dead-Letter Queue (DLQ)`:**
   - Calcula esperas exponenciales con *jitter* para evitar el problema de *Thundering Herd* y almacena los eventos agotados en la **DLQ** para re-dispararlos en 1 clic mediante `POST /api/v1/webhooks/dlq/{id}/replay`.

---

## 🐳 Despliegue Rápido (Docker Compose & ALpanel)

```bash
cp .env.example .env
docker compose up -d --build
```

- **Documentación Interactiva Scalar OpenAPI 3.1:** `http://localhost:8088/`
- **Estado de Salud y Circuit Breakers:** `http://localhost:8088/api/v1/health`

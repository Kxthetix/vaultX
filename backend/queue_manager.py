"""VaultX Queue Manager - RabbitMQ + Redis job orchestration"""
import aio_pika, logging
from backend.config import settings
logger = logging.getLogger("vaultx.queue")

connection = None
channel = None

async def init_queues():
    global connection, channel
    try:
        connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        channel = await connection.channel()
        await channel.declare_queue("scans", durable=True)
        await channel.declare_queue("agents", durable=True)
        await channel.declare_queue("reports", durable=True)
        logger.info("✅ RabbitMQ queues initialized")
    except Exception as e:
        logger.warning(f"RabbitMQ not available: {e}. Running without queue.")

async def publish_scan_job(scan_id: str):
    if not channel:
        return
    import json
    await channel.default_exchange.publish(
        aio_pika.Message(body=json.dumps({"scan_id": scan_id}).encode()),
        routing_key="scans"
    )

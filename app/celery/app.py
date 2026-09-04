from celery import Celery
from celery.app.amqp import Queues
from kombu import Queue

from app.config.config import redis_settings

celery_app = Celery(
    "Seamless_Fashion_api_tasks",
    broker=redis_settings.celery_broker_url,
    backend=redis_settings.celery_result_backend
)


celery_app.conf.update(
    #Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],

    #Time
    timezone="UTC",
    enable_utc=True,

    #Reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,

    #Worker Behaviour
    worker_prefetch_multiplier=1,

    #Results
    result_expires=3600,

    #Retry Connection
    broker_connection_retry_on_startup=True,

    #Routing
    task_default_queue="default",

    #Safety
    task_soft_time_limit=30,
    task_time_limit=60,
)


celery_app.conf.task_queues = (
    Queues("default"),

    Queue(
        name="email",
        routing_key="emails"
    )
)


celery_app.conf.task_routes = {
    "Seamless_Fashion_api_tasks.tasks.email_tasks.send_email": {
        "queue": "emails",
        "routing_key": "emails"
    }
}
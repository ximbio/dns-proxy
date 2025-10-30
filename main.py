import asyncio
import sys

from src.config import settings, load_rules
from src.policy import Policy
from src.resolver import Resolver
from src.doh_resolver import run_doh
from src.dot_resolver import run_dot

from loguru import logger

logger.remove()
logger.add(
    sys.stdout,
    colorize=True,
    level=settings.LOG_LEVEL,
    format="<green>{time:DD.MM.YY HH:mm:ss}</green> | <level>{level:<7}</level> | {message}"
)


async def main():
    rules = load_rules()

    policy = Policy(rules)
    resolver = Resolver(policy, settings.UPSTREAM_DNS)

    tasks = []
    if settings.USE_DOH:
        tasks.append(run_doh(resolver))
    else:
        logger.info("DoH Resolver is disabled. Set USE_DOH=1 env variable to enable.")
    
    if settings.USE_DOT:
        tasks.append(run_dot(resolver))
    else:
        logger.info("DoT Resolver is disabled. Set USE_DOT=1 env variable to enable.")

    await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
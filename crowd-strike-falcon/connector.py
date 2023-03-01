""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
# -----------------------------------------
# Crowdstrike Falcon
# -----------------------------------------

from .operations import operations, check_health
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('crowdstrike-falcon')


class Crowdstrike(Connector):
    def execute(self, config, operation, params, **kwargs):
        logger.info('In execute() Operation:[{}]'.format(operation))
        try:
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params)

    def check_health(self, config):
        logger.info('starting health check')
        check_health(config)
        logger.info('completed health check no errors')

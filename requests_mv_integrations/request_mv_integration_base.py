

import datetime as dt
import logging
import resource

# from requests_mv_integrations.logging import (
#     TuneLogging
# )
from requests_mv_integrations import (
    __version__
)
from requests_mv_integrations.support import (
    __LOGGER_NAME__
)
from logging_mv_integrations import (
    TuneLogging
)
from logging_mv_integrations.logging_format import (
    TuneLoggingFormat
)


# @brief Requests MV-Integrations base
#
# @namespace requests_mv_integrations.RequestMvIntegrationBase
class RequestMvIntegrationBase(object):
    """Requests MV-Integrations base
    """

    #  Timezone
    #  @var str
    __timezone = None

    #  Logger Handler
    #  @var str
    __logger_name = None

    #  Logger Format
    #  @var str
    __logger_format = None

    #  Logger Level
    #  @var int
    __logger_level = logging.NOTSET

    #  Logger
    #  @var object
    __req_logger = None

    #  Constructor
    #
    def __init__(
        self,
        req_logger=None,
        logger_name=None,
        logger_format=TuneLoggingFormat.JSON,
        logger_level=logging.NOTSET,
        timezone=None
    ):
        """Constructor

        :param logger_format:
        :param req_logger:
        :param logger_name:
        :param logger_level:
        :param timezone:
        """

        # print(__name__, '__init__')
        self.logger_format = logger_format
        self.time_start = dt.datetime.now()

        if logger_name is None:
            self.logger_name = __LOGGER_NAME__
        else:
            self.logger_name = logger_name

        if timezone is not None:
            self.timezone = timezone

        self.is_alive = True

        logging._checkLevel(logger_level)
        if logger_level != logging.NOTSET:
            self.logger_level = logger_level

        logging._checkLevel(self.logger_level)

        ru_maxrss_start = \
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        if req_logger:
            assert type(req_logger).__name__ == 'TuneLogging'
            req_logger.ru_maxrss_start = ru_maxrss_start
            self.req_logger = req_logger
        elif self.req_logger is None:
            # print('RequestMvIntegrationBase', '__init__')
            self.req_logger = TuneLogging(
                logger_level=self.logger_level,
                logger_name=self.logger_name,
                logger_format=self.logger_format,
                ru_maxrss_start=ru_maxrss_start
            )
        else:
            self.req_logger.ru_maxrss_start = ru_maxrss_start

        self.__data = None
        self.__count = 0

        # pprint({
        #     'logger_name': self.logger_name,
        #     'logger_level': self.logger_level,
        #     'logger_format': self.logger_format
        # })

    @property
    def logger_name(self):
        """Get Property: Logger Handler
        """
        return self.__logger_name

    @logger_name.setter
    def logger_name(self, value):
        """Set Property: Logger Handler
        """
        self.__logger_name = value

    @property
    def logger_format(self):
        """Get Property: Logger Format
        """
        return self.__logger_format

    @logger_format.setter
    def logger_format(self, value):
        """Set Property: Logger Format
        """
        self.__logger_format = value

    @property
    def logger_level(self):
        """Get Property: Logger Level
        """
        return self.__logger_level

    @logger_level.setter
    def logger_level(self, value):
        """Set Property: Logger Level
        """
        logger_level = value
        logging._checkLevel(logger_level)

        if self.__req_logger:
            self.__req_logger.logger_level = logger_level

        self.__logger_level = logger_level

    @property
    def req_logger(
        self
    ):
        """Get Property: Logger
        """
        if self.__req_logger is None:
            self.__req_logger = self.get_tune_logger()

        if self.__req_logger is not None:
            assert type(self.__req_logger).__name__ == 'TuneLogging'

        # print('req_logger.getter', type(self.__req_logger).__name__, id(self.__req_logger))
        return self.__req_logger

    @req_logger.setter
    def req_logger(self, value):
        """Set Property: Logger
        """
        if value is not None:
            assert type(value).__name__ == 'TuneLogging'

        # print('RequestMvIntegrationBase', 'req_logger.setter', type(value).__name__, id(value))
        self.__req_logger = value

    def get_tune_logger(
        self,
        logger_format=TuneLoggingFormat.JSON
    ):
        """Get instance of :class:`TuneLogging`
        Returns:
            :class:`TuneLogging`
        """
        # pprint({
        #     'logger_name': self.logger_name,
        #     'logger_level': self.logger_level,
        #     'logger_format': self.logger_format
        # })

        _logger_format = None
        if self.logger_format:
            _logger_format = self.logger_format
        if logger_format:
            if not TuneLoggingFormat.validate(logger_format):
                raise ValueError(
                    "Invalid 'logger_format': '{}'".format(
                        logger_format
                    )
                )
            _logger_format = logger_format

        req_logger = None
        if _logger_format:
            # print('RequestMvIntegrationBase', 'get_tune_logger')
            req_logger = TuneLogging(
                logger_name=self.logger_name,
                logger_level=self.logger_level,
                logger_format=_logger_format,
                logger_version=__version__
            )

        # print(req_logger, _logger_format)
        # print('get_tune_logger', type(req_logger).__name__, id(req_logger))
        return req_logger

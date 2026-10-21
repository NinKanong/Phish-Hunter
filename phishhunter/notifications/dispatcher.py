import logging
log=logging.getLogger(__name__)
def notify(message:str)->None: log.info("notification=%s",message)

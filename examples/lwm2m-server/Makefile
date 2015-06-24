# name of your application
APPLICATION = lwm2m-server

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

USEMODULE += wakaama

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP
CFLAGS += -DLWM2M_SERVER_MODE -DWITH_LOGS -DLWM2M_LITTLE_ENDIAN

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

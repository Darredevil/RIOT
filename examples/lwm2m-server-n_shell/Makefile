# name of your application
APPLICATION = lwm2m-server

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

USEMODULE += wakaama
USEMODULE += od
USEMODULE += uart0
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps
USEMODULE += ng_ipv6_default
USEMODULE += ng_udp
USEMODULE += ng_nativenet
USEMODULE += ng_netif_default
USEMODULE += auto_init_ng_netif
USEMODULE += ng_icmpv6_echo
INCLUDES += -I$(RIOTBASE)/sys/wakaama

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP
CFLAGS += -DLWM2M_SERVER_MODE -DWITH_LOGS -DLWM2M_LITTLE_ENDIAN -DLWM2M_BOOTSTRAP -g

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

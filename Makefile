# ==============================================================================
# make all/pdf/epub/mobi/clean
# ==============================================================================
GITBOOK = gitbook
RM = rm

TARGET = openssl编程
FORMATS = pdf epub mobi

.PHONY: all clean html $(FORMATS)

all: html $(FORMATS)

html:
	$(GITBOOK) build . $(TARGET)_html

$(FORMATS):
	$(GITBOOK) $@ . $(TARGET).$@
init:
	$(GITBOOK) init

preview:
	$(GITBOOK) serve
clean:
	-$(RM) -f $(addprefix $(TARGET)., $(FORMATS))
	-$(RM) -rf $(TARGET)_html

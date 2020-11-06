threadfpm: $(SAPI_THREADFPM_PATH)

$(SAPI_THREADFPM_PATH): $(PHP_GLOBAL_OBJS) $(PHP_BINARY_OBJS) $(PHP_FASTCGI_OBJS) $(PHP_THREADFPM_OBJS)
	$(BUILD_THREADFPM)

install-threadfpm: $(SAPI_THREADFPM_PATH)
	@echo "Installing PHP THREADFPM binary:  $(INSTALL_ROOT)$(sbindir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(sbindir)
	@$(INSTALL) -m 0755 $(SAPI_THREADFPM_PATH) $(INSTALL_ROOT)$(sbindir)/$(program_prefix)threadfpm$(program_suffix)$(EXEEXT)

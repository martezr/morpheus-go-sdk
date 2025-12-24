package morpheus

import "time"

var (
	// HealthPath is the API endpoint for health
	HealthPath = "/api/health"
)

// Process structures for use in request and response payloads
type CPU struct {
	Success        bool    `json:"success"`
	CPULoad        float64 `json:"cpuLoad"`
	CPUTotalLoad   float64 `json:"cpuTotalLoad"`
	ProcessorCount int     `json:"processorCount"`
	ProcessTime    float64 `json:"processTime"`
	SystemLoad     float64 `json:"systemLoad"`
	Status         string  `json:"status"`
}

type Memory struct {
	Success             bool    `json:"success"`
	MaxMemory           int64   `json:"maxMemory"`
	TotalMemory         int64   `json:"totalMemory"`
	FreeMemory          int     `json:"freeMemory"`
	UsedMemory          int     `json:"usedMemory"`
	SystemMemory        float64 `json:"systemMemory"`
	CommittedMemory     float64 `json:"committedMemory"`
	SystemFreeMemory    float64 `json:"systemFreeMemory"`
	SystemSwap          float64 `json:"systemSwap"`
	SystemFreeSwap      float64 `json:"systemFreeSwap"`
	SwapPercent         float64 `json:"swapPercent"`
	MemoryPercent       float64 `json:"memoryPercent"`
	SystemMemoryPercent float64 `json:"systemMemoryPercent"`
	Status              string  `json:"status"`
}
type Threads struct {
	Success           bool          `json:"success"`
	ThreadList        []interface{} `json:"threadList"`
	BusyThreads       []interface{} `json:"busyThreads"`
	BlockedThreads    []interface{} `json:"blockedThreads"`
	RunningThreads    []interface{} `json:"runningThreads"`
	TotalCPUTime      int64         `json:"totalCpuTime"`
	TotalThreads      int           `json:"totalThreads"`
	RunningWebThreads int           `json:"runningWebThreads"`
	Status            string        `json:"status"`
}

type ApplianceHealthDatabaseStats struct {
	AbortedClients                                  string `json:"Aborted_clients"`
	AbortedConnects                                 string `json:"Aborted_connects"`
	ACLCacheItemsCount                              string `json:"Acl_cache_items_count"`
	BinlogCacheDiskUse                              string `json:"Binlog_cache_disk_use"`
	BinlogCacheUse                                  string `json:"Binlog_cache_use"`
	BinlogStmtCacheDiskUse                          string `json:"Binlog_stmt_cache_disk_use"`
	BinlogStmtCacheUse                              string `json:"Binlog_stmt_cache_use"`
	BytesReceived                                   string `json:"Bytes_received"`
	BytesSent                                       string `json:"Bytes_sent"`
	CachingSha2PasswordRsaPublicKey                 string `json:"Caching_sha2_password_rsa_public_key"`
	ComAdminCommands                                string `json:"Com_admin_commands"`
	ComAssignToKeycache                             string `json:"Com_assign_to_keycache"`
	ComAlterDb                                      string `json:"Com_alter_db"`
	ComAlterEvent                                   string `json:"Com_alter_event"`
	ComAlterFunction                                string `json:"Com_alter_function"`
	ComAlterInstance                                string `json:"Com_alter_instance"`
	ComAlterProcedure                               string `json:"Com_alter_procedure"`
	ComAlterResourceGroup                           string `json:"Com_alter_resource_group"`
	ComAlterServer                                  string `json:"Com_alter_server"`
	ComAlterTable                                   string `json:"Com_alter_table"`
	ComAlterTablespace                              string `json:"Com_alter_tablespace"`
	ComAlterUser                                    string `json:"Com_alter_user"`
	ComAlterUserDefaultRole                         string `json:"Com_alter_user_default_role"`
	ComAnalyze                                      string `json:"Com_analyze"`
	ComBegin                                        string `json:"Com_begin"`
	ComBinlog                                       string `json:"Com_binlog"`
	ComCallProcedure                                string `json:"Com_call_procedure"`
	ComChangeDb                                     string `json:"Com_change_db"`
	ComChangeMaster                                 string `json:"Com_change_master"`
	ComChangeReplFilter                             string `json:"Com_change_repl_filter"`
	ComChangeReplicationSource                      string `json:"Com_change_replication_source"`
	ComCheck                                        string `json:"Com_check"`
	ComChecksum                                     string `json:"Com_checksum"`
	ComClone                                        string `json:"Com_clone"`
	ComCommit                                       string `json:"Com_commit"`
	ComCreateDb                                     string `json:"Com_create_db"`
	ComCreateEvent                                  string `json:"Com_create_event"`
	ComCreateFunction                               string `json:"Com_create_function"`
	ComCreateIndex                                  string `json:"Com_create_index"`
	ComCreateProcedure                              string `json:"Com_create_procedure"`
	ComCreateRole                                   string `json:"Com_create_role"`
	ComCreateServer                                 string `json:"Com_create_server"`
	ComCreateTable                                  string `json:"Com_create_table"`
	ComCreateResourceGroup                          string `json:"Com_create_resource_group"`
	ComCreateTrigger                                string `json:"Com_create_trigger"`
	ComCreateUdf                                    string `json:"Com_create_udf"`
	ComCreateUser                                   string `json:"Com_create_user"`
	ComCreateView                                   string `json:"Com_create_view"`
	ComCreateSpatialReferenceSystem                 string `json:"Com_create_spatial_reference_system"`
	ComDeallocSQL                                   string `json:"Com_dealloc_sql"`
	ComDelete                                       string `json:"Com_delete"`
	ComDeleteMulti                                  string `json:"Com_delete_multi"`
	ComDo                                           string `json:"Com_do"`
	ComDropDb                                       string `json:"Com_drop_db"`
	ComDropEvent                                    string `json:"Com_drop_event"`
	ComDropFunction                                 string `json:"Com_drop_function"`
	ComDropIndex                                    string `json:"Com_drop_index"`
	ComDropProcedure                                string `json:"Com_drop_procedure"`
	ComDropResourceGroup                            string `json:"Com_drop_resource_group"`
	ComDropRole                                     string `json:"Com_drop_role"`
	ComDropServer                                   string `json:"Com_drop_server"`
	ComDropSpatialReferenceSystem                   string `json:"Com_drop_spatial_reference_system"`
	ComDropTable                                    string `json:"Com_drop_table"`
	ComDropTrigger                                  string `json:"Com_drop_trigger"`
	ComDropUser                                     string `json:"Com_drop_user"`
	ComDropView                                     string `json:"Com_drop_view"`
	ComEmptyQuery                                   string `json:"Com_empty_query"`
	ComExecuteSQL                                   string `json:"Com_execute_sql"`
	ComExplainOther                                 string `json:"Com_explain_other"`
	ComFlush                                        string `json:"Com_flush"`
	ComGetDiagnostics                               string `json:"Com_get_diagnostics"`
	ComGrant                                        string `json:"Com_grant"`
	ComGrantRoles                                   string `json:"Com_grant_roles"`
	ComHaClose                                      string `json:"Com_ha_close"`
	ComHaOpen                                       string `json:"Com_ha_open"`
	ComHaRead                                       string `json:"Com_ha_read"`
	ComHelp                                         string `json:"Com_help"`
	ComImport                                       string `json:"Com_import"`
	ComInsert                                       string `json:"Com_insert"`
	ComInsertSelect                                 string `json:"Com_insert_select"`
	ComInstallComponent                             string `json:"Com_install_component"`
	ComInstallPlugin                                string `json:"Com_install_plugin"`
	ComKill                                         string `json:"Com_kill"`
	ComLoad                                         string `json:"Com_load"`
	ComLockInstance                                 string `json:"Com_lock_instance"`
	ComLockTables                                   string `json:"Com_lock_tables"`
	ComOptimize                                     string `json:"Com_optimize"`
	ComPreloadKeys                                  string `json:"Com_preload_keys"`
	ComPrepareSQL                                   string `json:"Com_prepare_sql"`
	ComPurge                                        string `json:"Com_purge"`
	ComPurgeBeforeDate                              string `json:"Com_purge_before_date"`
	ComReleaseSavepoint                             string `json:"Com_release_savepoint"`
	ComRenameTable                                  string `json:"Com_rename_table"`
	ComRenameUser                                   string `json:"Com_rename_user"`
	ComRepair                                       string `json:"Com_repair"`
	ComReplace                                      string `json:"Com_replace"`
	ComReplaceSelect                                string `json:"Com_replace_select"`
	ComReset                                        string `json:"Com_reset"`
	ComResignal                                     string `json:"Com_resignal"`
	ComRestart                                      string `json:"Com_restart"`
	ComRevoke                                       string `json:"Com_revoke"`
	ComRevokeAll                                    string `json:"Com_revoke_all"`
	ComRevokeRoles                                  string `json:"Com_revoke_roles"`
	ComRollback                                     string `json:"Com_rollback"`
	ComRollbackToSavepoint                          string `json:"Com_rollback_to_savepoint"`
	ComSavepoint                                    string `json:"Com_savepoint"`
	ComSelect                                       string `json:"Com_select"`
	ComSetOption                                    string `json:"Com_set_option"`
	ComSetPassword                                  string `json:"Com_set_password"`
	ComSetResourceGroup                             string `json:"Com_set_resource_group"`
	ComSetRole                                      string `json:"Com_set_role"`
	ComSignal                                       string `json:"Com_signal"`
	ComShowBinlogEvents                             string `json:"Com_show_binlog_events"`
	ComShowBinlogs                                  string `json:"Com_show_binlogs"`
	ComShowCharsets                                 string `json:"Com_show_charsets"`
	ComShowCollations                               string `json:"Com_show_collations"`
	ComShowCreateDb                                 string `json:"Com_show_create_db"`
	ComShowCreateEvent                              string `json:"Com_show_create_event"`
	ComShowCreateFunc                               string `json:"Com_show_create_func"`
	ComShowCreateProc                               string `json:"Com_show_create_proc"`
	ComShowCreateTable                              string `json:"Com_show_create_table"`
	ComShowCreateTrigger                            string `json:"Com_show_create_trigger"`
	ComShowDatabases                                string `json:"Com_show_databases"`
	ComShowEngineLogs                               string `json:"Com_show_engine_logs"`
	ComShowEngineMutex                              string `json:"Com_show_engine_mutex"`
	ComShowEngineStatus                             string `json:"Com_show_engine_status"`
	ComShowEvents                                   string `json:"Com_show_events"`
	ComShowErrors                                   string `json:"Com_show_errors"`
	ComShowFields                                   string `json:"Com_show_fields"`
	ComShowFunctionCode                             string `json:"Com_show_function_code"`
	ComShowFunctionStatus                           string `json:"Com_show_function_status"`
	ComShowGrants                                   string `json:"Com_show_grants"`
	ComShowKeys                                     string `json:"Com_show_keys"`
	ComShowMasterStatus                             string `json:"Com_show_master_status"`
	ComShowOpenTables                               string `json:"Com_show_open_tables"`
	ComShowPlugins                                  string `json:"Com_show_plugins"`
	ComShowPrivileges                               string `json:"Com_show_privileges"`
	ComShowProcedureCode                            string `json:"Com_show_procedure_code"`
	ComShowProcedureStatus                          string `json:"Com_show_procedure_status"`
	ComShowProcesslist                              string `json:"Com_show_processlist"`
	ComShowProfile                                  string `json:"Com_show_profile"`
	ComShowProfiles                                 string `json:"Com_show_profiles"`
	ComShowRelaylogEvents                           string `json:"Com_show_relaylog_events"`
	ComShowReplicas                                 string `json:"Com_show_replicas"`
	ComShowSlaveHosts                               string `json:"Com_show_slave_hosts"`
	ComShowReplicaStatus                            string `json:"Com_show_replica_status"`
	ComShowSlaveStatus                              string `json:"Com_show_slave_status"`
	ComShowStatus                                   string `json:"Com_show_status"`
	ComShowStorageEngines                           string `json:"Com_show_storage_engines"`
	ComShowTableStatus                              string `json:"Com_show_table_status"`
	ComShowTables                                   string `json:"Com_show_tables"`
	ComShowTriggers                                 string `json:"Com_show_triggers"`
	ComShowVariables                                string `json:"Com_show_variables"`
	ComShowWarnings                                 string `json:"Com_show_warnings"`
	ComShowCreateUser                               string `json:"Com_show_create_user"`
	ComShutdown                                     string `json:"Com_shutdown"`
	ComReplicaStart                                 string `json:"Com_replica_start"`
	ComSlaveStart                                   string `json:"Com_slave_start"`
	ComReplicaStop                                  string `json:"Com_replica_stop"`
	ComSlaveStop                                    string `json:"Com_slave_stop"`
	ComGroupReplicationStart                        string `json:"Com_group_replication_start"`
	ComGroupReplicationStop                         string `json:"Com_group_replication_stop"`
	ComStmtExecute                                  string `json:"Com_stmt_execute"`
	ComStmtClose                                    string `json:"Com_stmt_close"`
	ComStmtFetch                                    string `json:"Com_stmt_fetch"`
	ComStmtPrepare                                  string `json:"Com_stmt_prepare"`
	ComStmtReset                                    string `json:"Com_stmt_reset"`
	ComStmtSendLongData                             string `json:"Com_stmt_send_long_data"`
	ComTruncate                                     string `json:"Com_truncate"`
	ComUninstallComponent                           string `json:"Com_uninstall_component"`
	ComUninstallPlugin                              string `json:"Com_uninstall_plugin"`
	ComUnlockInstance                               string `json:"Com_unlock_instance"`
	ComUnlockTables                                 string `json:"Com_unlock_tables"`
	ComUpdate                                       string `json:"Com_update"`
	ComUpdateMulti                                  string `json:"Com_update_multi"`
	ComXaCommit                                     string `json:"Com_xa_commit"`
	ComXaEnd                                        string `json:"Com_xa_end"`
	ComXaPrepare                                    string `json:"Com_xa_prepare"`
	ComXaRecover                                    string `json:"Com_xa_recover"`
	ComXaRollback                                   string `json:"Com_xa_rollback"`
	ComXaStart                                      string `json:"Com_xa_start"`
	ComStmtReprepare                                string `json:"Com_stmt_reprepare"`
	Compression                                     string `json:"Compression"`
	CompressionAlgorithm                            string `json:"Compression_algorithm"`
	CompressionLevel                                string `json:"Compression_level"`
	ConnectionErrorsAccept                          string `json:"Connection_errors_accept"`
	ConnectionErrorsInternal                        string `json:"Connection_errors_internal"`
	ConnectionErrorsMaxConnections                  string `json:"Connection_errors_max_connections"`
	ConnectionErrorsPeerAddress                     string `json:"Connection_errors_peer_address"`
	ConnectionErrorsSelect                          string `json:"Connection_errors_select"`
	ConnectionErrorsTcpwrap                         string `json:"Connection_errors_tcpwrap"`
	Connections                                     string `json:"Connections"`
	CreatedTmpDiskTables                            string `json:"Created_tmp_disk_tables"`
	CreatedTmpFiles                                 string `json:"Created_tmp_files"`
	CreatedTmpTables                                string `json:"Created_tmp_tables"`
	CurrentTLSCa                                    string `json:"Current_tls_ca"`
	CurrentTLSCapath                                string `json:"Current_tls_capath"`
	CurrentTLSCert                                  string `json:"Current_tls_cert"`
	CurrentTLSCipher                                string `json:"Current_tls_cipher"`
	CurrentTLSCiphersuites                          string `json:"Current_tls_ciphersuites"`
	CurrentTLSCrl                                   string `json:"Current_tls_crl"`
	CurrentTLSCrlpath                               string `json:"Current_tls_crlpath"`
	CurrentTLSKey                                   string `json:"Current_tls_key"`
	CurrentTLSVersion                               string `json:"Current_tls_version"`
	DelayedErrors                                   string `json:"Delayed_errors"`
	DelayedInsertThreads                            string `json:"Delayed_insert_threads"`
	DelayedWrites                                   string `json:"Delayed_writes"`
	DeprecatedUseISProcesslistCount                 string `json:"Deprecated_use_i_s_processlist_count"`
	DeprecatedUseISProcesslistLastTimestamp         string `json:"Deprecated_use_i_s_processlist_last_timestamp"`
	ErrorLogBufferedBytes                           string `json:"Error_log_buffered_bytes"`
	ErrorLogBufferedEvents                          string `json:"Error_log_buffered_events"`
	ErrorLogExpiredEvents                           string `json:"Error_log_expired_events"`
	ErrorLogLatestWrite                             string `json:"Error_log_latest_write"`
	FlushCommands                                   string `json:"Flush_commands"`
	GlobalConnectionMemory                          string `json:"Global_connection_memory"`
	HandlerCommit                                   string `json:"Handler_commit"`
	HandlerDelete                                   string `json:"Handler_delete"`
	HandlerDiscover                                 string `json:"Handler_discover"`
	HandlerExternalLock                             string `json:"Handler_external_lock"`
	HandlerMrrInit                                  string `json:"Handler_mrr_init"`
	HandlerPrepare                                  string `json:"Handler_prepare"`
	HandlerReadFirst                                string `json:"Handler_read_first"`
	HandlerReadKey                                  string `json:"Handler_read_key"`
	HandlerReadLast                                 string `json:"Handler_read_last"`
	HandlerReadNext                                 string `json:"Handler_read_next"`
	HandlerReadPrev                                 string `json:"Handler_read_prev"`
	HandlerReadRnd                                  string `json:"Handler_read_rnd"`
	HandlerReadRndNext                              string `json:"Handler_read_rnd_next"`
	HandlerRollback                                 string `json:"Handler_rollback"`
	HandlerSavepoint                                string `json:"Handler_savepoint"`
	HandlerSavepointRollback                        string `json:"Handler_savepoint_rollback"`
	HandlerUpdate                                   string `json:"Handler_update"`
	HandlerWrite                                    string `json:"Handler_write"`
	InnodbBufferPoolDumpStatus                      string `json:"Innodb_buffer_pool_dump_status"`
	InnodbBufferPoolLoadStatus                      string `json:"Innodb_buffer_pool_load_status"`
	InnodbBufferPoolResizeStatus                    string `json:"Innodb_buffer_pool_resize_status"`
	InnodbBufferPoolResizeStatusCode                string `json:"Innodb_buffer_pool_resize_status_code"`
	InnodbBufferPoolResizeStatusProgress            string `json:"Innodb_buffer_pool_resize_status_progress"`
	InnodbBufferPoolPagesData                       string `json:"Innodb_buffer_pool_pages_data"`
	InnodbBufferPoolBytesData                       string `json:"Innodb_buffer_pool_bytes_data"`
	InnodbBufferPoolPagesDirty                      string `json:"Innodb_buffer_pool_pages_dirty"`
	InnodbBufferPoolBytesDirty                      string `json:"Innodb_buffer_pool_bytes_dirty"`
	InnodbBufferPoolPagesFlushed                    string `json:"Innodb_buffer_pool_pages_flushed"`
	InnodbBufferPoolPagesFree                       string `json:"Innodb_buffer_pool_pages_free"`
	InnodbBufferPoolPagesMisc                       string `json:"Innodb_buffer_pool_pages_misc"`
	InnodbBufferPoolPagesTotal                      string `json:"Innodb_buffer_pool_pages_total"`
	InnodbBufferPoolReadAheadRnd                    string `json:"Innodb_buffer_pool_read_ahead_rnd"`
	InnodbBufferPoolReadAhead                       string `json:"Innodb_buffer_pool_read_ahead"`
	InnodbBufferPoolReadAheadEvicted                string `json:"Innodb_buffer_pool_read_ahead_evicted"`
	InnodbBufferPoolReadRequests                    string `json:"Innodb_buffer_pool_read_requests"`
	InnodbBufferPoolReads                           string `json:"Innodb_buffer_pool_reads"`
	InnodbBufferPoolWaitFree                        string `json:"Innodb_buffer_pool_wait_free"`
	InnodbBufferPoolWriteRequests                   string `json:"Innodb_buffer_pool_write_requests"`
	InnodbDataFsyncs                                string `json:"Innodb_data_fsyncs"`
	InnodbDataPendingFsyncs                         string `json:"Innodb_data_pending_fsyncs"`
	InnodbDataPendingReads                          string `json:"Innodb_data_pending_reads"`
	InnodbDataPendingWrites                         string `json:"Innodb_data_pending_writes"`
	InnodbDataRead                                  string `json:"Innodb_data_read"`
	InnodbDataReads                                 string `json:"Innodb_data_reads"`
	InnodbDataWrites                                string `json:"Innodb_data_writes"`
	InnodbDataWritten                               string `json:"Innodb_data_written"`
	InnodbDblwrPagesWritten                         string `json:"Innodb_dblwr_pages_written"`
	InnodbDblwrWrites                               string `json:"Innodb_dblwr_writes"`
	InnodbRedoLogReadOnly                           string `json:"Innodb_redo_log_read_only"`
	InnodbRedoLogUUID                               string `json:"Innodb_redo_log_uuid"`
	InnodbRedoLogCheckpointLsn                      string `json:"Innodb_redo_log_checkpoint_lsn"`
	InnodbRedoLogCurrentLsn                         string `json:"Innodb_redo_log_current_lsn"`
	InnodbRedoLogFlushedToDiskLsn                   string `json:"Innodb_redo_log_flushed_to_disk_lsn"`
	InnodbRedoLogLogicalSize                        string `json:"Innodb_redo_log_logical_size"`
	InnodbRedoLogPhysicalSize                       string `json:"Innodb_redo_log_physical_size"`
	InnodbRedoLogCapacityResized                    string `json:"Innodb_redo_log_capacity_resized"`
	InnodbRedoLogResizeStatus                       string `json:"Innodb_redo_log_resize_status"`
	InnodbLogWaits                                  string `json:"Innodb_log_waits"`
	InnodbLogWriteRequests                          string `json:"Innodb_log_write_requests"`
	InnodbLogWrites                                 string `json:"Innodb_log_writes"`
	InnodbOsLogFsyncs                               string `json:"Innodb_os_log_fsyncs"`
	InnodbOsLogPendingFsyncs                        string `json:"Innodb_os_log_pending_fsyncs"`
	InnodbOsLogPendingWrites                        string `json:"Innodb_os_log_pending_writes"`
	InnodbOsLogWritten                              string `json:"Innodb_os_log_written"`
	InnodbPageSize                                  string `json:"Innodb_page_size"`
	InnodbPagesCreated                              string `json:"Innodb_pages_created"`
	InnodbPagesRead                                 string `json:"Innodb_pages_read"`
	InnodbPagesWritten                              string `json:"Innodb_pages_written"`
	InnodbRedoLogEnabled                            string `json:"Innodb_redo_log_enabled"`
	InnodbRowLockCurrentWaits                       string `json:"Innodb_row_lock_current_waits"`
	InnodbRowLockTime                               string `json:"Innodb_row_lock_time"`
	InnodbRowLockTimeAvg                            string `json:"Innodb_row_lock_time_avg"`
	InnodbRowLockTimeMax                            string `json:"Innodb_row_lock_time_max"`
	InnodbRowLockWaits                              string `json:"Innodb_row_lock_waits"`
	InnodbRowsDeleted                               string `json:"Innodb_rows_deleted"`
	InnodbRowsInserted                              string `json:"Innodb_rows_inserted"`
	InnodbRowsRead                                  string `json:"Innodb_rows_read"`
	InnodbRowsUpdated                               string `json:"Innodb_rows_updated"`
	InnodbSystemRowsDeleted                         string `json:"Innodb_system_rows_deleted"`
	InnodbSystemRowsInserted                        string `json:"Innodb_system_rows_inserted"`
	InnodbSystemRowsRead                            string `json:"Innodb_system_rows_read"`
	InnodbSystemRowsUpdated                         string `json:"Innodb_system_rows_updated"`
	InnodbSampledPagesRead                          string `json:"Innodb_sampled_pages_read"`
	InnodbSampledPagesSkipped                       string `json:"Innodb_sampled_pages_skipped"`
	InnodbNumOpenFiles                              string `json:"Innodb_num_open_files"`
	InnodbTruncatedStatusWrites                     string `json:"Innodb_truncated_status_writes"`
	InnodbUndoTablespacesTotal                      string `json:"Innodb_undo_tablespaces_total"`
	InnodbUndoTablespacesImplicit                   string `json:"Innodb_undo_tablespaces_implicit"`
	InnodbUndoTablespacesExplicit                   string `json:"Innodb_undo_tablespaces_explicit"`
	InnodbUndoTablespacesActive                     string `json:"Innodb_undo_tablespaces_active"`
	KeyBlocksNotFlushed                             string `json:"Key_blocks_not_flushed"`
	KeyBlocksUnused                                 string `json:"Key_blocks_unused"`
	KeyBlocksUsed                                   string `json:"Key_blocks_used"`
	KeyReadRequests                                 string `json:"Key_read_requests"`
	KeyReads                                        string `json:"Key_reads"`
	KeyWriteRequests                                string `json:"Key_write_requests"`
	KeyWrites                                       string `json:"Key_writes"`
	LastQueryCost                                   string `json:"Last_query_cost"`
	LastQueryPartialPlans                           string `json:"Last_query_partial_plans"`
	LockedConnects                                  string `json:"Locked_connects"`
	MaxExecutionTimeExceeded                        string `json:"Max_execution_time_exceeded"`
	MaxExecutionTimeSet                             string `json:"Max_execution_time_set"`
	MaxExecutionTimeSetFailed                       string `json:"Max_execution_time_set_failed"`
	MaxUsedConnections                              string `json:"Max_used_connections"`
	MaxUsedConnectionsTime                          string `json:"Max_used_connections_time"`
	NotFlushedDelayedRows                           string `json:"Not_flushed_delayed_rows"`
	OngoingAnonymousTransactionCount                string `json:"Ongoing_anonymous_transaction_count"`
	OpenFiles                                       string `json:"Open_files"`
	OpenStreams                                     string `json:"Open_streams"`
	OpenTableDefinitions                            string `json:"Open_table_definitions"`
	OpenTables                                      string `json:"Open_tables"`
	OpenedFiles                                     string `json:"Opened_files"`
	OpenedTableDefinitions                          string `json:"Opened_table_definitions"`
	OpenedTables                                    string `json:"Opened_tables"`
	PerformanceSchemaAccountsLost                   string `json:"Performance_schema_accounts_lost"`
	PerformanceSchemaCondClassesLost                string `json:"Performance_schema_cond_classes_lost"`
	PerformanceSchemaCondInstancesLost              string `json:"Performance_schema_cond_instances_lost"`
	PerformanceSchemaDigestLost                     string `json:"Performance_schema_digest_lost"`
	PerformanceSchemaFileClassesLost                string `json:"Performance_schema_file_classes_lost"`
	PerformanceSchemaFileHandlesLost                string `json:"Performance_schema_file_handles_lost"`
	PerformanceSchemaFileInstancesLost              string `json:"Performance_schema_file_instances_lost"`
	PerformanceSchemaHostsLost                      string `json:"Performance_schema_hosts_lost"`
	PerformanceSchemaIndexStatLost                  string `json:"Performance_schema_index_stat_lost"`
	PerformanceSchemaLockerLost                     string `json:"Performance_schema_locker_lost"`
	PerformanceSchemaMemoryClassesLost              string `json:"Performance_schema_memory_classes_lost"`
	PerformanceSchemaMetadataLockLost               string `json:"Performance_schema_metadata_lock_lost"`
	PerformanceSchemaMutexClassesLost               string `json:"Performance_schema_mutex_classes_lost"`
	PerformanceSchemaMutexInstancesLost             string `json:"Performance_schema_mutex_instances_lost"`
	PerformanceSchemaNestedStatementLost            string `json:"Performance_schema_nested_statement_lost"`
	PerformanceSchemaPreparedStatementsLost         string `json:"Performance_schema_prepared_statements_lost"`
	PerformanceSchemaProgramLost                    string `json:"Performance_schema_program_lost"`
	PerformanceSchemaRwlockClassesLost              string `json:"Performance_schema_rwlock_classes_lost"`
	PerformanceSchemaRwlockInstancesLost            string `json:"Performance_schema_rwlock_instances_lost"`
	PerformanceSchemaSessionConnectAttrsLongestSeen string `json:"Performance_schema_session_connect_attrs_longest_seen"`
	PerformanceSchemaSessionConnectAttrsLost        string `json:"Performance_schema_session_connect_attrs_lost"`
	PerformanceSchemaSocketClassesLost              string `json:"Performance_schema_socket_classes_lost"`
	PerformanceSchemaSocketInstancesLost            string `json:"Performance_schema_socket_instances_lost"`
	PerformanceSchemaStageClassesLost               string `json:"Performance_schema_stage_classes_lost"`
	PerformanceSchemaStatementClassesLost           string `json:"Performance_schema_statement_classes_lost"`
	PerformanceSchemaTableHandlesLost               string `json:"Performance_schema_table_handles_lost"`
	PerformanceSchemaTableInstancesLost             string `json:"Performance_schema_table_instances_lost"`
	PerformanceSchemaTableLockStatLost              string `json:"Performance_schema_table_lock_stat_lost"`
	PerformanceSchemaThreadClassesLost              string `json:"Performance_schema_thread_classes_lost"`
	PerformanceSchemaThreadInstancesLost            string `json:"Performance_schema_thread_instances_lost"`
	PerformanceSchemaUsersLost                      string `json:"Performance_schema_users_lost"`
	PreparedStmtCount                               string `json:"Prepared_stmt_count"`
	Queries                                         string `json:"Queries"`
	Questions                                       string `json:"Questions"`
	ReplicaOpenTempTables                           string `json:"Replica_open_temp_tables"`
	ResourceGroupSupported                          string `json:"Resource_group_supported"`
	RsaPublicKey                                    string `json:"Rsa_public_key"`
	SecondaryEngineExecutionCount                   string `json:"Secondary_engine_execution_count"`
	SelectFullJoin                                  string `json:"Select_full_join"`
	SelectFullRangeJoin                             string `json:"Select_full_range_join"`
	SelectRange                                     string `json:"Select_range"`
	SelectRangeCheck                                string `json:"Select_range_check"`
	SelectScan                                      string `json:"Select_scan"`
	SlaveOpenTempTables                             string `json:"Slave_open_temp_tables"`
	SlowLaunchThreads                               string `json:"Slow_launch_threads"`
	SlowQueries                                     string `json:"Slow_queries"`
	SortMergePasses                                 string `json:"Sort_merge_passes"`
	SortRange                                       string `json:"Sort_range"`
	SortRows                                        string `json:"Sort_rows"`
	SortScan                                        string `json:"Sort_scan"`
	SslAcceptRenegotiates                           string `json:"Ssl_accept_renegotiates"`
	SslAccepts                                      string `json:"Ssl_accepts"`
	SslCallbackCacheHits                            string `json:"Ssl_callback_cache_hits"`
	SslCipher                                       string `json:"Ssl_cipher"`
	SslCipherList                                   string `json:"Ssl_cipher_list"`
	SslClientConnects                               string `json:"Ssl_client_connects"`
	SslConnectRenegotiates                          string `json:"Ssl_connect_renegotiates"`
	SslCtxVerifyDepth                               string `json:"Ssl_ctx_verify_depth"`
	SslCtxVerifyMode                                string `json:"Ssl_ctx_verify_mode"`
	SslDefaultTimeout                               string `json:"Ssl_default_timeout"`
	SslFinishedAccepts                              string `json:"Ssl_finished_accepts"`
	SslFinishedConnects                             string `json:"Ssl_finished_connects"`
	SslServerNotAfter                               string `json:"Ssl_server_not_after"`
	SslServerNotBefore                              string `json:"Ssl_server_not_before"`
	SslSessionCacheHits                             string `json:"Ssl_session_cache_hits"`
	SslSessionCacheMisses                           string `json:"Ssl_session_cache_misses"`
	SslSessionCacheMode                             string `json:"Ssl_session_cache_mode"`
	SslSessionCacheOverflows                        string `json:"Ssl_session_cache_overflows"`
	SslSessionCacheSize                             string `json:"Ssl_session_cache_size"`
	SslSessionCacheTimeout                          string `json:"Ssl_session_cache_timeout"`
	SslSessionCacheTimeouts                         string `json:"Ssl_session_cache_timeouts"`
	SslSessionsReused                               string `json:"Ssl_sessions_reused"`
	SslUsedSessionCacheEntries                      string `json:"Ssl_used_session_cache_entries"`
	SslVerifyDepth                                  string `json:"Ssl_verify_depth"`
	SslVerifyMode                                   string `json:"Ssl_verify_mode"`
	SslVersion                                      string `json:"Ssl_version"`
	TableLocksImmediate                             string `json:"Table_locks_immediate"`
	TableLocksWaited                                string `json:"Table_locks_waited"`
	TableOpenCacheHits                              string `json:"Table_open_cache_hits"`
	TableOpenCacheMisses                            string `json:"Table_open_cache_misses"`
	TableOpenCacheOverflows                         string `json:"Table_open_cache_overflows"`
	TcLogMaxPagesUsed                               string `json:"Tc_log_max_pages_used"`
	TcLogPageSize                                   string `json:"Tc_log_page_size"`
	TcLogPageWaits                                  string `json:"Tc_log_page_waits"`
	TelemetryTracesSupported                        string `json:"Telemetry_traces_supported"`
	ThreadsCached                                   string `json:"Threads_cached"`
	ThreadsConnected                                string `json:"Threads_connected"`
	ThreadsCreated                                  string `json:"Threads_created"`
	ThreadsRunning                                  string `json:"Threads_running"`
	TLSLibraryVersion                               string `json:"Tls_library_version"`
	Uptime                                          string `json:"Uptime"`
	UptimeSinceFlushStatus                          string `json:"Uptime_since_flush_status"`
	Version                                         string `json:"version"`
}

type Scans struct {
	HandlerReadFirst   string `json:"Handler_read_first"`
	HandlerReadKey     string `json:"Handler_read_key"`
	HandlerReadLast    string `json:"Handler_read_last"`
	HandlerReadNext    string `json:"Handler_read_next"`
	HandlerReadPrev    string `json:"Handler_read_prev"`
	HandlerReadRnd     string `json:"Handler_read_rnd"`
	HandlerReadRndNext string `json:"Handler_read_rnd_next"`
}

type SlowQueries struct {
	Count int    `json:"count"`
	Time  int64  `json:"time"`
	Query string `json:"query"`
}

type InnodbStats struct {
	LargeMemory      int     `json:"largeMemory"`
	DictionaryMemory int     `json:"dictionaryMemory"`
	BufferPoolSize   int     `json:"bufferPoolSize"`
	FreeBuffers      int     `json:"freeBuffers"`
	DatabasePages    int     `json:"databasePages"`
	OldPages         int     `json:"oldPages"`
	PendingReads     int     `json:"pendingReads"`
	InsertsPerSecond float64 `json:"insertsPerSecond"`
	UpdatesPerSecond float64 `json:"updatesPerSecond"`
	DeletesPerSecond float64 `json:"deletesPerSecond"`
	ReadsPerSecond   float64 `json:"readsPerSecond"`
	BufferHitRate    float64 `json:"bufferHitRate"`
}

type Database struct {
	Success            bool                         `json:"success"`
	ConnectionList     []interface{}                `json:"connectionList"`
	BusyConnections    []interface{}                `json:"busyConnections"`
	MaxConnections     int                          `json:"maxConnections"`
	MaxUsedConnections int                          `json:"maxUsedConnections"`
	UsedConnections    int                          `json:"usedConnections"`
	AbortedConnections int                          `json:"abortedConnections"`
	InnodbStatus       interface{}                  `json:"innodbStatus"`
	Stats              ApplianceHealthDatabaseStats `json:"stats"`
	Scans              Scans                        `json:"scans"`
	SlowQueries        []SlowQueries                `json:"slowQueries"`
	InnodbStats        InnodbStats                  `json:"innodbStats"`
	ScanPercent        float64                      `json:"scanPercent"`
	Status             string                       `json:"status"`
}

type Files struct {
	Name      string  `json:"name"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Path      string  `json:"path"`
	Percent   float64 `json:"percent"`
	Total     int64   `json:"total"`
}

type Storage struct {
	Success   bool    `json:"success"`
	Files     []Files `json:"files"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	Total     int64   `json:"total"`
	Percent   float64 `json:"percent"`
	Status    string  `json:"status"`
}
type Master struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	IP   string `json:"ip"`
	Node string `json:"node"`
}
type Nodes struct {
	IP          string `json:"ip"`
	HeapPercent string `json:"heapPercent"`
	RAMPercent  string `json:"ramPercent"`
	CPUCount    string `json:"cpuCount"`
	LoadOne     string `json:"loadOne"`
	LoadFive    string `json:"loadFive"`
	LoadFifteen string `json:"loadFifteen"`
	Role        string `json:"role"`
	Master      string `json:"master"`
	Name        string `json:"name"`
}

type ApplianceHealthElasticStats struct {
	Status        string `json:"status"`
	ClusterName   string `json:"clusterName"`
	NodeTotal     string `json:"nodeTotal"`
	NodeData      string `json:"nodeData"`
	Shards        string `json:"shards"`
	Primary       string `json:"primary"`
	Relocating    string `json:"relocating"`
	Initializing  string `json:"initializing"`
	Unassigned    string `json:"unassigned"`
	PendingTasks  string `json:"pendingTasks"`
	ActivePercent string `json:"activePercent"`
}

type BadIndices struct {
	Health      string `json:"health"`
	Status      string `json:"status"`
	Index       string `json:"index"`
	UUID        string `json:"uuid"`
	Primary     string `json:"primary"`
	Replicas    string `json:"replicas"`
	Count       string `json:"count"`
	Deleted     string `json:"deleted"`
	PrimarySize string `json:"primarySize"`
	TotalSize   string `json:"totalSize"`
}

type Elastic struct {
	Success       bool                        `json:"success"`
	Status        string                      `json:"status"`
	Master        Master                      `json:"master"`
	Nodes         []Nodes                     `json:"nodes"`
	Stats         ApplianceHealthElasticStats `json:"stats"`
	Indices       []interface{}               `json:"indices"`
	BadIndices    []BadIndices                `json:"badIndices"`
	StatusMessage string                      `json:"statusMessage"`
}

type Queues struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Status string `json:"status"`
}

type Rabbit struct {
	Success     bool          `json:"success"`
	BusyQueues  []interface{} `json:"busyQueues"`
	ErrorQueues []interface{} `json:"errorQueues"`
	Status      string        `json:"status"`
	Queues      []Queues      `json:"queues"`
}

type Health struct {
	Success       bool      `json:"success"`
	StatusMessage string    `json:"statusMessage"`
	ApplianceURL  string    `json:"applianceUrl"`
	BuildVersion  string    `json:"buildVersion"`
	UUID          string    `json:"uuid"`
	SetupNeeded   bool      `json:"setupNeeded"`
	Date          time.Time `json:"date"`
	CPU           CPU       `json:"cpu"`
	Memory        Memory    `json:"memory"`
	Threads       Threads   `json:"threads"`
	Database      Database  `json:"database"`
	Storage       Storage   `json:"storage"`
	Elastic       Elastic   `json:"elastic"`
	Rabbit        Rabbit    `json:"rabbit"`
}

// GetHealthResult structure parses the list alerts response payload
type GetHealthResult struct {
	Health  Health            `json:"health"`
	Success bool              `json:"success"`
	Message string            `json:"msg"`
	Errors  map[string]string `json:"errors"`
	Meta    *MetaResult       `json:"meta"`
}

// GetHealth get health
func (client *Client) GetApplianceHealth(req *Request) (*Response, error) {
	return client.Execute(&Request{
		Method:      "GET",
		Path:        HealthPath,
		QueryParams: req.QueryParams,
		Result:      &GetHealthResult{},
	})
}

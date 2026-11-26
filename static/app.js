// app.js

// State management
let state = {
    activeTab: 'anomalies', // 'explorer', 'analytics' or 'anomalies'
    filters: {
        table: 'all',
        exporter: '',
        ipDir: 'any',
        ip: '',
        src: '',
        dst: '',
        portDir: 'any',
        port: '',
        sport: '',
        dport: '',
        proto: '',
        conditions: [],
        logic: 'AND',
        timeRange: '24h' // linked to top-right select
    },
    pagination: {
        limit: 50,
        offset: 0,
        total: 0
    },
    auditPagination: {
        limit: 50,
        offset: 0,
        total: 0
    },
    anomaliesPagination: {
        limit: 50,
        offset: 0,
        total: 0
    },
    ipAliasesPagination: {
        limit: 25,
        offset: 0,
        total: 0,
        search: ''
    },
    auditFilters: {
        src: '',
        dst: '',
        port: '',
        flag: ''
    },
    anomaliesFilters: {
        ipDir: 'any',
        ip: '',
        src: '',
        dst: '',
        portDir: 'any',
        port: '',
        sport: '',
        dport: '',
        proto: '',
        flag: '',
        conditions: [],
        logic: 'AND'
    },
    sorting: {
        by: 'ts',
        order: 'desc'
    },
    auditSorting: {
        by: 'ts',
        order: 'desc'
    },
    records: [], // Cache for current page records
    charts: {},  // Store Chart.js instances
    abortControllers: {} // Active AbortController instances for cancelling stale requests
};

function getAbortSignal(key) {
    if (state.abortControllers[key]) {
        state.abortControllers[key].abort();
    }
    const ctrl = new AbortController();
    state.abortControllers[key] = ctrl;
    return ctrl.signal;
}

// UI Elements
const els = {
    btnTabExplorer: document.getElementById('btn-tab-explorer'),
    btnTabAnalytics: document.getElementById('btn-tab-analytics'),
    btnTabAnomalies: document.getElementById('btn-tab-anomalies'),
    btnTabSettingsTrigger: document.getElementById('btn-tab-settings-trigger'),
    btnTabManagement: document.getElementById('btn-tab-management'),
    btnTabAliases: document.getElementById('btn-tab-aliases'),
    btnTabAudit: document.getElementById('btn-tab-audit'),
    viewExplorer: document.getElementById('view-explorer'),
    viewAnalytics: document.getElementById('view-analytics'),
    viewAnomalies: document.getElementById('view-anomalies'),
    viewDataManagement: document.getElementById('view-data-management'),
    viewAliasManager: document.getElementById('view-alias-manager'),
    viewAudit: document.getElementById('view-audit'),
    btnTabCollector: document.getElementById('btn-tab-collector'),
    viewCollectorSettings: document.getElementById('view-collector-settings'),
    formCollectorSettings: document.getElementById('form-collector-settings'),
    inputSettingNetflowPort: document.getElementById('input-setting-netflow-port'),
    inputSettingIpfixPort: document.getElementById('input-setting-ipfix-port'),
    collectorSettingsStatus: document.getElementById('collector-settings-status'),
    cleanupBeforeDate: document.getElementById('cleanup-before-date'),
    btnExecuteCleanup: document.getElementById('btn-execute-cleanup'),
    cleanupStatusMessage: document.getElementById('cleanup-status-message'),
    
    // Auditing Elements
    btnTriggerAudit: document.getElementById('btn-trigger-audit'),
    auditLastRunTime: document.getElementById('audit-last-run-time'),
    auditNextRunTime: document.getElementById('audit-next-run-time'),
    auditLastRunStatus: document.getElementById('audit-last-run-status'),
    auditLastRunMatches: document.getElementById('audit-last-run-matches'),
    auditLastRunMessage: document.getElementById('audit-last-run-message'),
    auditTriggerStatus: document.getElementById('audit-trigger-status'),
    auditTriggerModal: document.getElementById('audit-trigger-modal'),
    btnCloseTriggerModal: document.getElementById('btn-close-trigger-modal'),
    btnCancelTriggerAudit: document.getElementById('btn-cancel-trigger-audit'),
    btnConfirmTriggerAudit: document.getElementById('btn-confirm-trigger-audit'),
    auditOptionLastRunLabel: document.getElementById('audit-option-last-run-label'),
    auditCustomStartTime: document.getElementById('audit-custom-start-time'),
    auditRuleForm: document.getElementById('audit-rule-form'),
    auditInputIp: document.getElementById('audit-input-ip'),
    auditInputPort: document.getElementById('audit-input-port'),
    auditRuleStatusMessage: document.getElementById('audit-rule-status-message'),
    auditRulesTbody: document.getElementById('audit-rules-tbody'),
    btnExportRules: document.getElementById('btn-export-rules'),
    btnImportRules: document.getElementById('btn-import-rules'),
    inputImportRules: document.getElementById('input-import-rules'),
    btnClearRules: document.getElementById('btn-clear-rules'),
    
    // Edit Audit Rule Modal
    modalEditAuditRule: document.getElementById('modal-edit-audit-rule'),
    btnCloseEditRuleModal: document.getElementById('btn-close-edit-rule-modal'),
    btnCancelEditRule: document.getElementById('btn-cancel-edit-rule'),
    formEditAuditRule: document.getElementById('form-edit-audit-rule'),
    editRuleId: document.getElementById('edit-rule-id'),
    editRuleSelectIpType: document.getElementById('edit-rule-select-ip-type'),
    editRuleInputIp: document.getElementById('edit-rule-input-ip'),
    editRuleInputPort: document.getElementById('edit-rule-input-port'),
    editRuleErrorMessage: document.getElementById('edit-rule-error-message'),
    
    // Audit Search / Table / Pagination
    auditPageSize: document.getElementById('audit-page-size'),
    btnClearAuditMatches: document.getElementById('btn-clear-audit-matches'),
    btnExportAuditMatches: document.getElementById('btn-export-audit-matches'),
    auditTotalFiltered: document.getElementById('audit-total-filtered'),
    auditPagination: document.getElementById('audit-pagination'),
    auditMatchesTbody: document.getElementById('audit-matches-tbody'),
    filterAuditSrc: document.getElementById('filter-audit-src'),
    filterAuditDst: document.getElementById('filter-audit-dst'),
    filterAuditPort: document.getElementById('filter-audit-port'),
    filterAuditFlag: document.getElementById('filter-audit-flag'),
    btnApplyAuditSearch: document.getElementById('btn-apply-audit-search'),
    btnResetAuditSearch: document.getElementById('btn-reset-audit-search'),

    // Anomalies Report elements
    anomaliesPageSize: document.getElementById('anomalies-page-size'),
    btnExportAnomalies: document.getElementById('btn-export-anomalies'),
    anomaliesTotalFiltered: document.getElementById('anomalies-total-filtered'),
    anomaliesPagination: document.getElementById('anomalies-pagination'),
    anomaliesTbody: document.getElementById('anomalies-tbody'),
    filterAnomaliesIpDir: document.getElementById('filter-anomalies-ip-dir'),
    filterAnomaliesIpType: document.getElementById('filter-anomalies-ip-type'),
    filterAnomaliesIpVal: document.getElementById('filter-anomalies-ip-val'),
    filterAnomaliesPortDir: document.getElementById('filter-anomalies-port-dir'),
    filterAnomaliesPortVal: document.getElementById('filter-anomalies-port-val'),
    filterAnomaliesProto: document.getElementById('filter-anomalies-proto'),
    filterAnomaliesFlag: document.getElementById('filter-anomalies-flag'),
    btnApplyAnomaliesSearch: document.getElementById('btn-apply-anomalies-search'),
    btnResetAnomaliesSearch: document.getElementById('btn-reset-anomalies-search'),
    
    globalTimeRange: document.getElementById('global-time-range'),
    btnRefresh: document.getElementById('btn-refresh'),
    timeRangeSummary: document.getElementById('time-range-summary'),
    
    // KPIs
    kpiTotalFlows: document.getElementById('kpi-total-flows'),
    kpiTotalBytes: document.getElementById('kpi-total-bytes'),
    kpiTotalPackets: document.getElementById('kpi-total-packets'),
    kpiTotalExporters: document.getElementById('kpi-total-exporters'),
    
    // Filters Form
    filterForm: document.getElementById('filter-form'),
    filterIpDir: document.getElementById('filter-ip-dir'),
    filterIpType: document.getElementById('filter-ip-type'),
    filterIpVal: document.getElementById('filter-ip-val'),
    filterPortDir: document.getElementById('filter-port-dir'),
    filterPortVal: document.getElementById('filter-port-val'),
    filterSrc: document.getElementById('filter-src'),
    filterDst: document.getElementById('filter-dst'),
    filterSport: document.getElementById('filter-sport'),
    filterDport: document.getElementById('filter-dport'),
    btnResetFilters: document.getElementById('btn-reset-filters'),
    btnAddFlowCondition: document.getElementById('btn-add-flow-condition'),
    flowConditionsList: document.getElementById('flow-conditions-list'),
    btnAddAnomaliesCondition: document.getElementById('btn-add-anomalies-condition'),
    anomaliesConditionsList: document.getElementById('anomalies-conditions-list'),
    filterProtoGroup: document.getElementById('filter-proto-group'),
    chartContextMenu: document.getElementById('chart-context-menu'),
    
    // Table
    flowsTbody: document.getElementById('flows-tbody'),
    flowRangeStart: document.getElementById('flow-range-start'),
    flowRangeEnd: document.getElementById('flow-range-end'),
    flowTotalFiltered: document.getElementById('flow-total-filtered'),
    pageSize: document.getElementById('page-size'),
    flowsPagination: document.getElementById('flows-pagination'),
    
    // Modal
    detailsModal: document.getElementById('details-modal'),
    btnCloseModal: document.getElementById('btn-close-modal'),
    detailRuleSection: document.getElementById('detail-rule-section'),
    detailRuleIp: document.getElementById('detail-rule-ip'),
    detailRulePort: document.getElementById('detail-rule-port'),
    detailMatchFlag: document.getElementById('detail-match-flag'),
    detailMatchTs: document.getElementById('detail-match-ts'),
    detailId: document.getElementById('detail-id'),
    detailTs: document.getElementById('detail-ts'),
    detailType: document.getElementById('detail-type'),
    detailExporter: document.getElementById('detail-exporter'),
    detailSrc: document.getElementById('detail-src'),
    detailSrcDomain: document.getElementById('detail-src-domain'),
    detailDst: document.getElementById('detail-dst'),
    detailDstDomain: document.getElementById('detail-dst-domain'),
    detailProto: document.getElementById('detail-proto'),
    detailOctets: document.getElementById('detail-octets'),
    detailPackets: document.getElementById('detail-packets'),
    detailRawJson: document.getElementById('detail-raw-json'),

    // Users & New Settings Elements
    btnTabUsers: document.getElementById('btn-tab-users'),
    viewUserManagement: document.getElementById('view-user-management'),
    inputRetentionDays: document.getElementById('input-retention-days'),
    inputRetentionTime: document.getElementById('input-retention-time'),
    selectRetentionEnabled: document.getElementById('select-retention-enabled'),
    retentionLastRunTime: document.getElementById('retention-last-run-time'),
    retentionNextRunTime: document.getElementById('retention-next-run-time'),
    retentionLastMessage: document.getElementById('retention-last-message'),
    retentionStatusBadge: document.getElementById('retention-status-badge'),
    formRetentionSettings: document.getElementById('form-retention-settings'),
    btnSaveRetention: document.getElementById('btn-save-retention'),
    btnRunRetentionNow: document.getElementById('btn-run-retention-now'),
    retentionStatusAlert: document.getElementById('retention-status-alert'),
    formAddCollectorCidr: document.getElementById('form-add-collector-cidr'),
    inputNewCollectorCidr: document.getElementById('input-new-collector-cidr'),
    inputNewCollectorCidrDesc: document.getElementById('input-new-collector-cidr-desc'),
    collectorCidrsStatus: document.getElementById('collector-cidrs-status'),
    collectorCidrsTbody: document.getElementById('collector-cidrs-tbody'),
    btnOpenAddUser: document.getElementById('btn-open-add-user'),
    usersTbody: document.getElementById('users-tbody'),
    usersStatusMessage: document.getElementById('users-status-message'),
    viewLogin: document.getElementById('view-login'),
    formLogin: document.getElementById('form-login'),
    loginUsername: document.getElementById('login-username'),
    loginPassword: document.getElementById('login-password'),
    loginErrorMessage: document.getElementById('login-error-message'),
    btnDoLogin: document.getElementById('btn-do-login'),
    btnLogout: document.getElementById('btn-logout'),
    btnOpenChangePwd: document.getElementById('btn-open-change-pwd'),
    currentUsername: document.getElementById('current-username'),
    currentUserRole: document.getElementById('current-user-role'),
    userAvatarInitial: document.getElementById('user-avatar-initial'),
    modalAddUser: document.getElementById('modal-add-user'),
    formAddUser: document.getElementById('form-add-user'),
    inputNewUserName: document.getElementById('input-new-user-name'),
    inputNewUserPassword: document.getElementById('input-new-user-password'),
    selectNewUserRole: document.getElementById('select-new-user-role'),
    addUserError: document.getElementById('add-user-error'),
    btnCloseAddUserModal: document.getElementById('btn-close-add-user-modal'),
    btnCancelAddUser: document.getElementById('btn-cancel-add-user'),
    modalResetUserPassword: document.getElementById('modal-reset-user-password'),
    formResetUserPassword: document.getElementById('form-reset-user-password'),
    resetTargetUserId: document.getElementById('reset-target-user-id'),
    resetTargetUsername: document.getElementById('reset-target-username'),
    inputAdminNewPwd: document.getElementById('input-admin-new-pwd'),
    resetPwdError: document.getElementById('reset-pwd-error'),
    btnCloseResetPwdModal: document.getElementById('btn-close-reset-pwd-modal'),
    btnCancelResetPwd: document.getElementById('btn-cancel-reset-pwd'),
    modalChangePassword: document.getElementById('modal-change-password'),
    formChangeOwnPassword: document.getElementById('form-change-own-password'),
    inputCurrentPwd: document.getElementById('input-current-pwd'),
    inputNewOwnPwd: document.getElementById('input-new-own-pwd'),
    inputNewOwnPwdConfirm: document.getElementById('input-new-own-pwd-confirm'),
    changePwdError: document.getElementById('change-pwd-error'),
    btnCloseChangePwdModal: document.getElementById('btn-close-change-pwd-modal'),
    btnCancelChangePwd: document.getElementById('btn-cancel-change-pwd'),
    modalMustChangePassword: document.getElementById('modal-must-change-password'),
    formMustChangePassword: document.getElementById('form-must-change-password'),
    inputForceOldPwd: document.getElementById('input-force-old-pwd'),
    inputForceNewPwd: document.getElementById('input-force-new-pwd'),
    inputForceNewPwdConfirm: document.getElementById('input-force-new-pwd-confirm'),
    forcePwdError: document.getElementById('force-pwd-error')
};

// HTML Escaping Utility
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Toast Notification System (Top-Right Floating Alert)
function showToast(message, type = 'success', title = null) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
        iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #10b981; width: 20px; height: 20px;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
        if (!title) title = '診斷完成';
    } else if (type === 'error') {
        iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #ef4444; width: 20px; height: 20px;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
        if (!title) title = '更新失敗';
    } else if (type === 'warning') {
        iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #f59e0b; width: 20px; height: 20px;"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`;
        if (!title) title = '提醒';
    } else {
        iconSvg = `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="color: #6366f1; width: 20px; height: 20px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
        if (!title) title = '通知';
    }

    toast.innerHTML = `
        <div style="flex-shrink: 0; display: flex; align-items: center; justify-content: center; margin-top: 2px;">
            ${iconSvg}
        </div>
        <div class="toast-body">
            <div class="toast-title">${escapeHtml(title)}</div>
            ${message ? `<div class="toast-message">${escapeHtml(message)}</div>` : ''}
        </div>
        <button class="toast-close" title="關閉" type="button">&times;</button>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    let isDismissed = false;
    const dismiss = () => {
        if (isDismissed) return;
        isDismissed = true;
        toast.classList.add('hide');
        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 280);
    };

    if (closeBtn) closeBtn.addEventListener('click', dismiss);

    container.appendChild(toast);
    setTimeout(dismiss, 4000);
}

// Universal Refresh / Diagnose Feedback Runner (Spin Arrow, disable button, & pop Toast)
async function executeRefreshWithFeedback(btn, asyncAction, successTitle = '資料已更新', successMessage = '') {
    if (!btn) {
        if (asyncAction) await asyncAction();
        return;
    }
    
    // Avoid double-clicks while running
    if (btn.classList.contains('btn-refresh-loading')) return;

    btn.classList.add('btn-refresh-loading');
    btn.disabled = true;

    // Minimum delay ensures the user visually sees the satisfying rotation ("體感")
    const minDelay = new Promise(resolve => setTimeout(resolve, 650));

    try {
        await Promise.all([
            asyncAction ? asyncAction() : Promise.resolve(),
            minDelay
        ]);
        showToast(successMessage, 'success', successTitle);
    } catch (err) {
        if (err.name !== 'AbortError') {
            console.error('Refresh action failed:', err);
            showToast(err.message || '連線或處理異常，請檢查網路狀態', 'error', '處理失敗');
        }
    } finally {
        btn.classList.remove('btn-refresh-loading');
        btn.disabled = false;
        btn.querySelectorAll('svg, i, .lucide').forEach(el => el.classList.remove('icon-spinning', 'spin-animation'));
        if (window.lucide) window.lucide.createIcons();
    }
}

// Sidebar Collapsible Mini-Mode Functions
function initSidebarToggle() {
    const sidebar = document.querySelector('.sidebar');
    const toggleBtn = document.getElementById('btn-toggle-sidebar');
    if (!sidebar || !toggleBtn) return;

    // Check localStorage preference
    const savedState = localStorage.getItem('sidebar-collapsed');
    if (savedState === 'true') {
        sidebar.classList.add('collapsed');
        updateSidebarToggleBtn(true);
    } else {
        updateSidebarToggleBtn(false);
    }

    toggleBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const isCollapsed = sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar-collapsed', isCollapsed ? 'true' : 'false');
        updateSidebarToggleBtn(isCollapsed);

        setTimeout(() => {
            window.dispatchEvent(new Event('resize'));
        }, 260);
    });
}

function setSidebarCollapsed(collapsed) {
    const sidebar = document.querySelector('.sidebar');
    if (!sidebar) return;
    if (collapsed) {
        sidebar.classList.add('collapsed');
    } else {
        sidebar.classList.remove('collapsed');
    }
    localStorage.setItem('sidebar-collapsed', collapsed ? 'true' : 'false');
    updateSidebarToggleBtn(collapsed);
    setTimeout(() => {
        window.dispatchEvent(new Event('resize'));
    }, 260);
}

function updateSidebarToggleBtn(isCollapsed) {
    const toggleBtn = document.getElementById('btn-toggle-sidebar');
    if (!toggleBtn) return;
    toggleBtn.title = isCollapsed ? '展開側邊欄' : '收合側邊欄';
    const closeIcon = toggleBtn.querySelector('.toggle-icon-collapse');
    const openIcon = toggleBtn.querySelector('.toggle-icon-expand');
    if (closeIcon) closeIcon.style.display = isCollapsed ? 'none' : 'block';
    if (openIcon) openIcon.style.display = isCollapsed ? 'block' : 'none';
}

// Initialization
document.addEventListener('DOMContentLoaded', async () => {
    // Re-initialize Lucide Icons
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        lucide.createIcons();
    }
    
    initSidebarToggle();
    setupConditionBuilders();
    renderConditions('flow');
    renderConditions('anomalies');
    setupEventListeners();
    setupHeaderSorting();
    updateHeaderSortIcons();
    setupAuditHeaderSorting();
    updateAuditHeaderSortIcons();
    setupColumnToggles();
    setupDropdowns();
    
    // Check authentication first
    const isAuth = await checkAuth();
    if (isAuth) {
        fetchExporterDropdown();
        fetchPortAliases();
        fetchIpAliases();
        switchTab('anomalies');
    }
});

// Setup Event Listeners
function setupEventListeners() {
    // IP Type Select Show/Hide Inputs for General
    const filterIpType = document.getElementById('filter-ip-type');
    const filterIpVal = document.getElementById('filter-ip-val');
    if (filterIpType && filterIpVal) {
        filterIpType.addEventListener('change', () => {
            filterIpVal.style.display = filterIpType.value === 'custom' ? 'block' : 'none';
            if (filterIpType.value !== 'custom') {
                filterIpVal.value = '';
            }
        });
    }

    // IP Type Select Show/Hide Inputs for Anomalies
    const filterAnomaliesIpType = document.getElementById('filter-anomalies-ip-type');
    const filterAnomaliesIpVal = document.getElementById('filter-anomalies-ip-val');
    if (filterAnomaliesIpType && filterAnomaliesIpVal) {
        filterAnomaliesIpType.addEventListener('change', () => {
            filterAnomaliesIpVal.style.display = filterAnomaliesIpType.value === 'custom' ? 'block' : 'none';
            if (filterAnomaliesIpType.value !== 'custom') {
                filterAnomaliesIpVal.value = '';
            }
        });
    }

    // Legacy IP Type fallback handlers
    const filterSrcType = document.getElementById('filter-src-type');
    const filterSrcInput = document.getElementById('filter-src');
    if (filterSrcType && filterSrcInput && filterSrcInput.type !== 'hidden') {
        filterSrcType.addEventListener('change', () => {
            filterSrcInput.style.display = filterSrcType.value === 'custom' ? 'block' : 'none';
            if (filterSrcType.value !== 'custom') {
                filterSrcInput.value = '';
            }
        });
    }

    const filterDstType = document.getElementById('filter-dst-type');
    const filterDstInput = document.getElementById('filter-dst');
    if (filterDstType && filterDstInput && filterDstInput.type !== 'hidden') {
        filterDstType.addEventListener('change', () => {
            filterDstInput.style.display = filterDstType.value === 'custom' ? 'block' : 'none';
            if (filterDstType.value !== 'custom') {
                filterDstInput.value = '';
            }
        });
    }

    const auditSelectIpType = document.getElementById('audit-select-ip-type');
    const auditInputIp = document.getElementById('audit-input-ip');
    if (auditSelectIpType && auditInputIp) {
        auditSelectIpType.addEventListener('change', () => {
            auditInputIp.style.display = auditSelectIpType.value === 'custom' ? 'block' : 'none';
            if (auditSelectIpType.value !== 'custom') {
                auditInputIp.value = '';
            }
        });
    }

    // Close chart context menu on click outside or Escape
    document.addEventListener('click', (e) => {
        const menu = document.getElementById('chart-context-menu');
        if (menu && menu.style.display !== 'none' && !e.target.closest('#chart-context-menu')) {
            hideChartContextMenu();
        }
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideChartContextMenu();
        }
    });

    // Tabs Navigation
    els.btnTabExplorer.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('explorer');
    });
    
    els.btnTabAnalytics.addEventListener('click', (e) => {
        e.preventDefault();
        switchTab('analytics');
    });

    if (els.btnTabAnomalies) {
        els.btnTabAnomalies.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('anomalies');
        });
    }

    if (els.btnTabSettingsTrigger) {
        els.btnTabSettingsTrigger.addEventListener('click', (e) => {
            e.preventDefault();
            const sidebar = document.querySelector('.sidebar');
            if (sidebar && sidebar.classList.contains('collapsed')) {
                setSidebarCollapsed(false);
            }
            const submenu = document.querySelector('#menu-settings .submenu');
            const chevron = els.btnTabSettingsTrigger.querySelector('.chevron-icon');
            if (submenu) {
                const isOpen = submenu.style.display === 'flex';
                submenu.style.display = isOpen ? 'none' : 'flex';
                if (chevron) {
                    chevron.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(-180deg)';
                }
            }
        });
    }

    if (els.btnTabManagement) {
        els.btnTabManagement.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('data-management');
        });
    }

    if (els.btnTabAliases) {
        els.btnTabAliases.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('aliases');
        });
    }

    if (els.btnTabAudit) {
        els.btnTabAudit.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('audit');
        });
    }

    if (els.btnTabCollector) {
        els.btnTabCollector.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('collector');
        });
    }

    if (els.btnTabUsers) {
        els.btnTabUsers.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab('users');
        });
    }

    // Retention Policy Listeners
    if (els.formRetentionSettings) {
        els.formRetentionSettings.addEventListener('submit', (e) => {
            e.preventDefault();
            saveRetentionSettings();
        });
    }

    if (els.btnRunRetentionNow) {
        els.btnRunRetentionNow.addEventListener('click', () => {
            runRetentionNow();
        });
    }

    // Collector CIDR Listeners
    if (els.formAddCollectorCidr) {
        els.formAddCollectorCidr.addEventListener('submit', (e) => {
            e.preventDefault();
            addCollectorCidr();
        });
    }

    // User Management Listeners
    if (els.btnOpenAddUser) {
        els.btnOpenAddUser.addEventListener('click', () => {
            openAddUserModal();
        });
    }

    if (els.btnCloseAddUserModal) {
        els.btnCloseAddUserModal.addEventListener('click', closeAddUserModal);
    }
    if (els.btnCancelAddUser) {
        els.btnCancelAddUser.addEventListener('click', closeAddUserModal);
    }
    if (els.formAddUser) {
        els.formAddUser.addEventListener('submit', (e) => {
            e.preventDefault();
            submitCreateUser();
        });
    }

    // User Password Reset Modal Listeners
    if (els.btnCloseResetPwdModal) {
        els.btnCloseResetPwdModal.addEventListener('click', closeResetPwdModal);
    }
    if (els.btnCancelResetPwd) {
        els.btnCancelResetPwd.addEventListener('click', closeResetPwdModal);
    }
    if (els.formResetUserPassword) {
        els.formResetUserPassword.addEventListener('submit', (e) => {
            e.preventDefault();
            submitResetUserPassword();
        });
    }

    // Change Own Password Modal Listeners
    if (els.btnOpenChangePwd) {
        els.btnOpenChangePwd.addEventListener('click', () => {
            openChangePwdModal();
        });
    }
    if (els.btnCloseChangePwdModal) {
        els.btnCloseChangePwdModal.addEventListener('click', closeChangePwdModal);
    }
    if (els.btnCancelChangePwd) {
        els.btnCancelChangePwd.addEventListener('click', closeChangePwdModal);
    }
    if (els.formChangeOwnPassword) {
        els.formChangeOwnPassword.addEventListener('submit', (e) => {
            e.preventDefault();
            submitChangeOwnPassword();
        });
    }

    // Force Password Change Listener (First login)
    if (els.formMustChangePassword) {
        els.formMustChangePassword.addEventListener('submit', (e) => {
            e.preventDefault();
            submitForceChangePassword();
        });
    }

    // Auth Login & Logout
    if (els.formLogin) {
        els.formLogin.addEventListener('submit', (e) => {
            e.preventDefault();
            handleLogin();
        });
    }

    if (els.btnLogout) {
        els.btnLogout.addEventListener('click', () => {
            handleLogout();
        });
    }

    if (els.formCollectorSettings) {
        els.formCollectorSettings.addEventListener('submit', (e) => {
            e.preventDefault();
            saveCollectorSettings();
        });
    }

    if (els.auditRuleForm) {
        els.auditRuleForm.addEventListener('submit', (e) => {
            e.preventDefault();
            submitAuditRule();
        });
    }

    // Edit Audit Rule Modal listeners
    if (els.editRuleSelectIpType && els.editRuleInputIp) {
        els.editRuleSelectIpType.addEventListener('change', () => {
            els.editRuleInputIp.style.display = els.editRuleSelectIpType.value === 'custom' ? 'block' : 'none';
            if (els.editRuleSelectIpType.value !== 'custom') {
                els.editRuleInputIp.value = '';
            }
        });
    }

    if (els.btnCloseEditRuleModal) {
        els.btnCloseEditRuleModal.addEventListener('click', closeEditRuleModal);
    }
    if (els.btnCancelEditRule) {
        els.btnCancelEditRule.addEventListener('click', closeEditRuleModal);
    }
    if (els.formEditAuditRule) {
        els.formEditAuditRule.addEventListener('submit', submitEditAuditRule);
    }
    window.addEventListener('click', (e) => {
        if (els.modalEditAuditRule && e.target === els.modalEditAuditRule) {
            closeEditRuleModal();
        }
    });

    if (els.btnTriggerAudit) {
        els.btnTriggerAudit.addEventListener('click', () => {
            const rangeSelect = document.getElementById('select-quick-audit-range');
            const rangeVal = rangeSelect ? rangeSelect.value : '24h';
            triggerManualAudit(null, rangeVal);
        });
    }

    // Audit Subtab Switcher listeners
    const btnAuditSubtabScenarios = document.getElementById('btn-audit-subtab-scenarios');
    const btnAuditSubtabLegacy = document.getElementById('btn-audit-subtab-legacy');
    const btnAuditSubtabIntel = document.getElementById('btn-audit-subtab-intel');
    if (btnAuditSubtabScenarios) {
        btnAuditSubtabScenarios.addEventListener('click', () => switchAuditSubtab('scenarios'));
    }
    if (btnAuditSubtabLegacy) {
        btnAuditSubtabLegacy.addEventListener('click', () => switchAuditSubtab('legacy'));
    }
    if (btnAuditSubtabIntel) {
        btnAuditSubtabIntel.addEventListener('click', () => switchAuditSubtab('intel'));
    }

    // Modal toggle radio inputs visibility
    const radioOptions = document.querySelectorAll('input[name="audit-range-option"]');
    radioOptions.forEach(radio => {
        radio.addEventListener('change', () => {
            if (els.auditCustomStartTime) {
                els.auditCustomStartTime.style.display = (radio.value === 'custom') ? 'block' : 'none';
            }
        });
    });

    // Close trigger modal triggers
    const closeTriggerModal = () => {
        if (els.auditTriggerModal) {
            els.auditTriggerModal.classList.remove('active');
        }
    };
    if (els.btnCloseTriggerModal) {
        els.btnCloseTriggerModal.addEventListener('click', closeTriggerModal);
    }
    if (els.btnCancelTriggerAudit) {
        els.btnCancelTriggerAudit.addEventListener('click', closeTriggerModal);
    }

    // Confirm trigger audit
    if (els.btnConfirmTriggerAudit) {
        els.btnConfirmTriggerAudit.addEventListener('click', () => {
            closeTriggerModal();
            
            const selectedOption = document.querySelector('input[name="audit-range-option"]:checked')?.value || 'last-run';
            let startTime = null;
            let timeRange = null;
            
            if (selectedOption === 'all-time') {
                timeRange = 'all';
            } else if (selectedOption === 'last-run') {
                timeRange = 'last-run';
            } else if (selectedOption === 'custom') {
                if (!els.auditCustomStartTime.value) {
                    alert('請選擇自訂的開始時間！');
                    return;
                }
                startTime = els.auditCustomStartTime.value; // e.g. "2026-07-09T10:30"
            }
            
            triggerManualAudit(startTime, timeRange);
        });
    }

    if (els.btnClearAuditMatches) {
        els.btnClearAuditMatches.addEventListener('click', () => {
            clearAuditMatches();
        });
    }
    
    if (els.auditPageSize) {
        els.auditPageSize.addEventListener('change', () => {
            state.auditPagination.limit = parseInt(els.auditPageSize.value);
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        });
    }

    if (els.btnApplyAuditSearch) {
        els.btnApplyAuditSearch.addEventListener('click', () => {
            state.auditFilters.src = els.filterAuditSrc.value.trim();
            state.auditFilters.dst = els.filterAuditDst.value.trim();
            state.auditFilters.port = els.filterAuditPort.value.trim();
            state.auditFilters.flag = els.filterAuditFlag.value;
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        });
    }

    if (els.btnResetAuditSearch) {
        els.btnResetAuditSearch.addEventListener('click', () => {
            els.filterAuditSrc.value = '';
            els.filterAuditDst.value = '';
            els.filterAuditPort.value = '';
            els.filterAuditFlag.value = '';
            state.auditFilters.src = '';
            state.auditFilters.dst = '';
            state.auditFilters.port = '';
            state.auditFilters.flag = '';
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        });
    }

    if (els.btnExportAuditMatches) {
        els.btnExportAuditMatches.addEventListener('click', () => {
            let url = `/api/audit/matches/export?`;
            const params = [];
            if (state.auditFilters.src) params.push(`src=${encodeURIComponent(state.auditFilters.src)}`);
            if (state.auditFilters.dst) params.push(`dst=${encodeURIComponent(state.auditFilters.dst)}`);
            if (state.auditFilters.port) params.push(`port=${encodeURIComponent(state.auditFilters.port)}`);
            if (state.auditFilters.flag) params.push(`flag=${encodeURIComponent(state.auditFilters.flag)}`);
            window.open(url + params.join('&'), '_blank');
        });
    }

    if (els.anomaliesPageSize) {
        els.anomaliesPageSize.addEventListener('change', () => {
            state.anomaliesPagination.limit = parseInt(els.anomaliesPageSize.value);
            state.anomaliesPagination.offset = 0;
            fetchAnomalousReport();
        });
    }

    if (els.btnApplyAnomaliesSearch) {
        els.btnApplyAnomaliesSearch.addEventListener('click', () => {
            applyAnomaliesFiltersFromForm();
            state.anomaliesPagination.offset = 0;
            executeRefreshWithFeedback(
                els.btnApplyAnomaliesSearch,
                async () => {
                    await fetchAnomalousReport();
                    await fetchAnomalousReportStats();
                },
                '資料已更新',
                '已根據篩選條件重新過濾詳細流量列表。'
            );
        });
    }

    if (els.btnResetAnomaliesSearch) {
        els.btnResetAnomaliesSearch.addEventListener('click', () => {
            state.anomaliesFilters.conditions = [];
            state.anomaliesFilters.logic = 'AND';
            renderConditions('anomalies');
            const aFlagEl = document.getElementById('filter-anomalies-flag');
            if (aFlagEl) aFlagEl.value = '';
            const drillBanner = document.getElementById('anomalies-drill-banner');
            if (drillBanner) drillBanner.style.display = 'none';
            
            applyAnomaliesFiltersFromForm();
            state.anomaliesPagination.offset = 0;
            executeRefreshWithFeedback(
                els.btnResetAnomaliesSearch,
                async () => {
                    await fetchAnomalousReport();
                    await fetchAnomalousReportStats();
                },
                '資料已更新',
                '已重設篩選條件並重新整理流量列表。'
            );
        });
    }

    if (els.btnExportAnomalies) {
        els.btnExportAnomalies.addEventListener('click', () => {
            let url = `/api/audit/matches/export?`;
            const params = [];
            if (state.anomaliesFilters.ip) params.push(`ip=${encodeURIComponent(state.anomaliesFilters.ip)}`);
            if (state.anomaliesFilters.src) params.push(`src=${encodeURIComponent(state.anomaliesFilters.src)}`);
            if (state.anomaliesFilters.dst) params.push(`dst=${encodeURIComponent(state.anomaliesFilters.dst)}`);
            if (state.anomaliesFilters.port) params.push(`port=${encodeURIComponent(state.anomaliesFilters.port)}`);
            if (state.anomaliesFilters.sport) params.push(`sport=${encodeURIComponent(state.anomaliesFilters.sport)}`);
            if (state.anomaliesFilters.dport) params.push(`dport=${encodeURIComponent(state.anomaliesFilters.dport)}`);
            if (state.anomaliesFilters.proto) params.push(`proto=${encodeURIComponent(state.anomaliesFilters.proto)}`);
            if (state.anomaliesFilters.flag) params.push(`flag=${encodeURIComponent(state.anomaliesFilters.flag)}`);
            
            // Dynamic multi-conditions
            if (state.anomaliesFilters.conditions && state.anomaliesFilters.conditions.length > 0) {
                const validConds = state.anomaliesFilters.conditions.map(c => {
                    let finalVal = c.val;
                    if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                        if (c.ipType && c.ipType !== 'custom') {
                            finalVal = c.ipType;
                        }
                    }
                    return { field: c.field, val: finalVal };
                }).filter(c => c.val && String(c.val).trim() !== '');

                if (validConds.length > 0) {
                    params.push(`conditions=${encodeURIComponent(JSON.stringify(validConds))}`);
                    params.push(`logic=${encodeURIComponent(state.anomaliesFilters.logic || 'AND')}`);
                }
            }

            window.open(url + params.join('&'), '_blank');
        });
    }

    els.btnExecuteCleanup.addEventListener('click', () => {
        executeCleanup();
    });

    if (els.btnExportRules) {
        els.btnExportRules.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/audit/rules/export');
                if (!res.ok) throw new Error('Export request failed');
                const data = await res.json();
                
                // Trigger download
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'netflow_audit_rules_backup.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showAuditRuleStatus('盤查規則備份檔已成功下載', 'success');
            } catch (err) {
                showAuditRuleStatus(`匯出失敗: ${err.message}`, 'error');
            }
        });
    }

    if (els.btnImportRules && els.inputImportRules) {
        els.btnImportRules.addEventListener('click', () => {
            els.inputImportRules.click();
        });

        els.inputImportRules.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (event) => {
                try {
                    const payload = JSON.parse(event.target.result);
                    if (!Array.isArray(payload)) {
                        throw new Error('無效的備份檔格式（需為規則的 JSON 陣列）');
                    }

                    const res = await fetch('/api/audit/rules/import', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    
                    if (res.ok) {
                        showAuditRuleStatus(data.message || '匯入成功', 'success');
                        fetchAuditRules(); // Reload rule table
                    } else {
                        showAuditRuleStatus(data.detail || '匯入失敗', 'error');
                    }
                } catch (err) {
                    showAuditRuleStatus(`解析匯入檔案失敗: ${err.message}`, 'error');
                }
                // Reset file input value to allow importing the same file again
                els.inputImportRules.value = '';
            };
            reader.readAsText(file);
        });
    }

    if (els.btnClearRules) {
        els.btnClearRules.addEventListener('click', async () => {
            if (!confirm('您確定要清除所有的流量盤查規則嗎？此動作將無法復原。')) {
                return;
            }
            try {
                const res = await fetch('/api/audit/rules', { method: 'DELETE' });
                const data = await res.json();
                if (res.ok) {
                    showAuditRuleStatus('所有盤查規則已成功清除！', 'success');
                    fetchAuditRules(); // Reload rules list
                } else {
                    showAuditRuleStatus(data.detail || '清除失敗', 'error');
                }
            } catch (err) {
                showAuditRuleStatus(`清除錯誤: ${err.message}`, 'error');
            }
        });
    }
    
    // Global actions
    els.globalTimeRange.addEventListener('change', () => {
        const value = els.globalTimeRange.value;
        state.filters.timeRange = value;
        
        const customWrapper = document.getElementById('global-custom-time-wrapper');
        if (value === 'custom') {
            customWrapper.style.display = 'flex';
        } else {
            customWrapper.style.display = 'none';
            // Clear custom start/end times in state and inputs when switching back to relative
            state.filters.startTime = '';
            state.filters.endTime = '';
            document.getElementById('global-start-time').value = '';
            document.getElementById('global-end-time').value = '';
        }
        
        updateTimeRangeSubtitle();
        state.pagination.offset = 0; // Reset pagination
        refreshData();
    });

    const globalStart = document.getElementById('global-start-time');
    const globalEnd = document.getElementById('global-end-time');
    
    globalStart.addEventListener('change', () => {
        state.filters.startTime = toTaiwanLocalTimestamp(globalStart.value);
        state.pagination.offset = 0; // Reset pagination
        updateTimeRangeSubtitle();
        refreshData();
    });
    
    globalEnd.addEventListener('change', () => {
        state.filters.endTime = toTaiwanLocalTimestamp(globalEnd.value);
        state.pagination.offset = 0; // Reset pagination
        updateTimeRangeSubtitle();
        refreshData();
    });
    
    els.btnRefresh.addEventListener('click', (e) => {
        e.preventDefault();
        const isAnomalies = document.querySelector('.tab-content.active#tab-anomalies');
        if (isAnomalies && diagState.mode === 'smart') {
            executeRefreshWithFeedback(
                els.btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                '智慧情境診斷已完成，已同步最新數據。'
            );
        } else if (isAnomalies && diagState.mode === 'legacy') {
            executeRefreshWithFeedback(
                els.btnRefresh,
                async () => {
                    await fetchAnomalousReport();
                    await fetchAnomalousReportStats();
                },
                '資料已更新',
                '詳細流量清單與統計圖表已更新。'
            );
        } else {
            executeRefreshWithFeedback(
                els.btnRefresh,
                async () => {
                    fetchExporterDropdown();
                    await refreshData();
                },
                '資料已更新',
                '流量儀表板數據已更新至最新狀態。'
            );
        }
    });

    // Detailed Flow List refresh button
    const btnRefreshLegacy = document.getElementById('btn-refresh-legacy-anomalies');
    if (btnRefreshLegacy) {
        btnRefreshLegacy.addEventListener('click', (e) => {
            e.preventDefault();
            executeRefreshWithFeedback(
                btnRefreshLegacy,
                async () => {
                    await fetchAnomalousReport();
                    await fetchAnomalousReportStats();
                },
                '資料已更新',
                '詳細流量列表與統計圖表已更新至最新狀態。'
            );
        });
    }

    // System audit matches refresh button
    const btnRefreshAudit = document.getElementById('btn-refresh-audit');
    if (btnRefreshAudit) {
        btnRefreshAudit.addEventListener('click', (e) => {
            e.preventDefault();
            executeRefreshWithFeedback(
                btnRefreshAudit,
                () => fetchAuditMatches(),
                '資料已更新',
                '稽核記錄清單已更新至最新狀態。'
            );
        });
    }
    
    // Filters form submit & reset
    els.filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        applyFiltersFromForm();
        state.pagination.offset = 0;
        refreshData();
    });
    
    els.btnResetFilters.addEventListener('click', () => {
        els.filterForm.reset();
        state.filters.conditions = [];
        state.filters.logic = 'AND';
        renderConditions('flow');

        // Reset all custom checkboxes to checked by default
        const checkboxes = document.querySelectorAll('.custom-dropdown input[type="checkbox"]');
        checkboxes.forEach(cb => cb.checked = true);
        applyFiltersFromForm();
        updateDropdownLabels();
        state.pagination.offset = 0;
        refreshData();
    });
    
    // Page size dropdown
    els.pageSize.addEventListener('change', () => {
        state.pagination.limit = parseInt(els.pageSize.value);
        state.pagination.offset = 0;
        fetchFlows();
    });
    
    // CSV Export button
    const btnExportCsv = document.getElementById('btn-export-csv');
    if (btnExportCsv) {
        btnExportCsv.addEventListener('click', () => {
            const params = getFlowQueryParams();
            window.location.href = `/api/flows/export?${params.toString()}`;
        });
    }
    
    // Details modal close
    els.btnCloseModal.addEventListener('click', closeModal);
    els.detailsModal.addEventListener('click', (e) => {
        if (e.target === els.detailsModal) {
            closeModal();
        }
    });
    
    // Close modal on ESC key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && els.detailsModal.classList.contains('active')) {
            closeModal();
        }
    });
    
    // Port Alias form listener
    const formPortAlias = document.getElementById('form-port-alias');
    if (formPortAlias) {
        formPortAlias.addEventListener('submit', handleSavePortAlias);
    }

    // IP Alias form listener
    const formIpAlias = document.getElementById('form-ip-alias');
    if (formIpAlias) {
        formIpAlias.addEventListener('submit', handleSaveIpAlias);
    }

    // Segmented toggle button listeners for Alias Manager
    const btnToggleIp = document.getElementById('btn-toggle-ip');
    const btnTogglePort = document.getElementById('btn-toggle-port');
    const containerIpAlias = document.getElementById('container-ip-alias');
    const containerPortAlias = document.getElementById('container-port-alias');

    if (btnToggleIp && btnTogglePort && containerIpAlias && containerPortAlias) {
        btnToggleIp.addEventListener('click', () => {
            btnToggleIp.classList.add('active');
            btnTogglePort.classList.remove('active');
            containerIpAlias.style.display = 'block';
            containerPortAlias.style.display = 'none';
        });

        btnTogglePort.addEventListener('click', () => {
            btnTogglePort.classList.add('active');
            btnToggleIp.classList.remove('active');
            containerPortAlias.style.display = 'block';
            containerIpAlias.style.display = 'none';
        });
    }

    // Export / Import Backup bindings
    const btnExportAliases = document.getElementById('btn-export-aliases');
    const btnImportAliases = document.getElementById('btn-import-aliases');
    const inputImportAliases = document.getElementById('input-import-aliases');

    if (btnExportAliases) {
        btnExportAliases.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/aliases/export');
                if (!res.ok) throw new Error('Export request failed');
                const data = await res.json();
                
                // Trigger download
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'netflow_aliases_backup.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showIpAliasStatus('別名備份檔已成功下載', 'success');
            } catch (err) {
                showIpAliasStatus(`匯出失敗: ${err.message}`, 'error');
            }
        });
    }

    if (btnImportAliases && inputImportAliases) {
        btnImportAliases.addEventListener('click', () => {
            inputImportAliases.click();
        });

        inputImportAliases.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async (event) => {
                try {
                    const payload = JSON.parse(event.target.result);
                    if (!payload.ip_aliases || !payload.port_aliases) {
                        throw new Error('無效的備份檔格式（缺少 ip_aliases 或 port_aliases）');
                    }

                    const res = await fetch('/api/aliases/import', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(payload)
                    });

                    if (!res.ok) throw new Error('API import request failed');
                    const result = await res.json();
                    
                    showIpAliasStatus(result.message, 'success');
                    fetchIpAliases();
                    fetchPortAliases();
                    fetchFlows();
                } catch (err) {
                    showIpAliasStatus(`匯入失敗: ${err.message}`, 'error');
                } finally {
                    // Reset input
                    inputImportAliases.value = '';
                }
            };
            reader.readAsText(file);
        });
    }

    const btnClearAliases = document.getElementById('btn-clear-aliases');
    if (btnClearAliases) {
        btnClearAliases.addEventListener('click', async () => {
            if (!confirm('您確定要清空所有自訂 IP 與 Port 別名嗎？此動作將無法復原。')) return;
            
            try {
                const res = await fetch('/api/aliases/clear', { method: 'POST' });
                if (!res.ok) throw new Error('Clear request failed');
                const result = await res.json();
                
                showIpAliasStatus(result.message, 'success');
                showPortAliasStatus(result.message, 'success');
                
                fetchIpAliases();
                fetchPortAliases();
                fetchFlows();
            } catch (err) {
                showIpAliasStatus(`清除失敗: ${err.message}`, 'error');
            }
        });
    }

    // IP aliases search
    const searchInput = document.getElementById('input-search-ip-aliases');
    if (searchInput) {
        let timeout = null;
        searchInput.addEventListener('input', () => {
            clearTimeout(timeout);
            timeout = setTimeout(() => {
                state.ipAliasesPagination.search = searchInput.value;
                state.ipAliasesPagination.offset = 0;
                fetchIpAliases();
            }, 300);
        });
    }

    // IP aliases pagination clicks
    const btnIpPrev = document.getElementById('btn-ip-aliases-prev');
    if (btnIpPrev) {
        btnIpPrev.addEventListener('click', () => {
            state.ipAliasesPagination.offset = Math.max(0, state.ipAliasesPagination.offset - state.ipAliasesPagination.limit);
            fetchIpAliases();
        });
    }

    const btnIpNext = document.getElementById('btn-ip-aliases-next');
    if (btnIpNext) {
        btnIpNext.addEventListener('click', () => {
            state.ipAliasesPagination.offset += state.ipAliasesPagination.limit;
            fetchIpAliases();
        });
    }
}

// Tab Switching logic
function switchTab(tabName) {
    state.activeTab = tabName;
    
    // Hide filter card if settings/report tabs are active
    const isSettingsTab = ['data-management', 'aliases', 'audit', 'anomalies', 'collector', 'users'].includes(tabName);
    const filterCard = document.querySelector('.filter-card');
    if (filterCard) {
        filterCard.style.display = isSettingsTab ? 'none' : 'block';
    }
    
    // Show/hide top header and KPI grid (only needed for Flow Explorer and Traffic Analytics)
    const showHeaderKpi = ['explorer', 'analytics'].includes(tabName);
    const topHeader = document.querySelector('.top-header');
    const kpiGrid = document.querySelector('.kpi-grid');
    if (topHeader) {
        topHeader.style.display = showHeaderKpi ? 'flex' : 'none';
    }
    if (kpiGrid) {
        kpiGrid.style.display = showHeaderKpi ? 'grid' : 'none';
    }
    
    const columnsDropdown = document.getElementById('dropdown-columns');
    if (columnsDropdown) {
        const formGroup = columnsDropdown.closest('.form-group');
        if (formGroup) {
            formGroup.style.display = tabName === 'explorer' ? 'block' : 'none';
        }
    }
    
    // Remove active from all tabs and views
    els.btnTabExplorer.classList.remove('active');
    els.btnTabAnalytics.classList.remove('active');
    if (els.btnTabAnomalies) els.btnTabAnomalies.classList.remove('active');
    if (els.btnTabSettingsTrigger) els.btnTabSettingsTrigger.classList.remove('active');
    if (els.btnTabManagement) els.btnTabManagement.classList.remove('active');
    if (els.btnTabAliases) els.btnTabAliases.classList.remove('active');
    if (els.btnTabAudit) els.btnTabAudit.classList.remove('active');
    if (els.btnTabCollector) els.btnTabCollector.classList.remove('active');
    if (els.btnTabUsers) els.btnTabUsers.classList.remove('active');
    
    els.viewExplorer.classList.remove('active');
    els.viewAnalytics.classList.remove('active');
    if (els.viewAnomalies) els.viewAnomalies.classList.remove('active');
    if (els.viewDataManagement) els.viewDataManagement.classList.remove('active');
    if (els.viewAliasManager) els.viewAliasManager.classList.remove('active');
    if (els.viewAudit) els.viewAudit.classList.remove('active');
    if (els.viewCollectorSettings) els.viewCollectorSettings.classList.remove('active');
    if (els.viewUserManagement) els.viewUserManagement.classList.remove('active');
    
    // Activate selected tab and view
    if (tabName === 'explorer') {
        els.btnTabExplorer.classList.add('active');
        els.viewExplorer.classList.add('active');
        refreshData();
    } else if (tabName === 'analytics') {
        els.btnTabAnalytics.classList.add('active');
        els.viewAnalytics.classList.add('active');
        refreshData();
    } else if (tabName === 'anomalies') {
        if (els.btnTabAnomalies) els.btnTabAnomalies.classList.add('active');
        if (els.viewAnomalies) els.viewAnomalies.classList.add('active');
        refreshAnomaliesActiveView();
    } else {
        // Settings sub-tabs routing
        let activeBtn = null;
        let activeView = null;
        
        if (tabName === 'data-management') {
            activeBtn = els.btnTabManagement;
            activeView = els.viewDataManagement;
            fetchRetentionSettings();
        } else if (tabName === 'aliases') {
            activeBtn = els.btnTabAliases;
            activeView = els.viewAliasManager;
        } else if (tabName === 'audit') {
            activeBtn = els.btnTabAudit;
            activeView = els.viewAudit;
            fetchScenariosList();
            fetchAuditRules();
            fetchAuditStatus();
            fetchAuditMatches();
            fetchThreatIntelCache();
        } else if (tabName === 'collector') {
            activeBtn = els.btnTabCollector;
            activeView = els.viewCollectorSettings;
            fetchCollectorSettings();
            fetchCollectorCidrs();
            fetchAthenacSettings();
            fetchThreatIntelSettings();
        } else if (tabName === 'users') {
            activeBtn = els.btnTabUsers;
            activeView = els.viewUserManagement;
            fetchUsersList();
        }
        
        if (activeBtn) activeBtn.classList.add('active');
        if (activeView) activeView.classList.add('active');
        
        // Auto-expand Settings submenu if collapsed
        const submenu = document.querySelector('#menu-settings .submenu');
        const chevron = document.querySelector('#btn-tab-settings-trigger .chevron-icon');
        if (submenu) {
            submenu.style.display = 'flex';
            if (chevron) {
                chevron.style.transform = 'rotate(-180deg)';
            }
        }
    }

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

// Update time summary subtitle
function updateTimeRangeSubtitle() {
    const range = state.filters.timeRange;
    let label = '過去 24 小時流量總覽';
    if (range === '1h') label = '過去 1 小時流量總覽';
    if (range === '7d') label = '過去 7 天流量總覽';
    if (range === 'all') label = '所有歷史流量總覽';
    if (range === 'custom') {
        const startVal = document.getElementById('global-start-time').value;
        const endVal = document.getElementById('global-end-time').value;
        if (startVal && endVal) {
            label = `自 ${startVal.replace('T', ' ')} 至 ${endVal.replace('T', ' ')} 之流量總覽`;
        } else {
            label = '自訂時間區間之流量總覽';
        }
    }
    els.timeRangeSummary.innerText = label;
}

// Read form elements into state filters
function applyFiltersFromForm() {
    state.filters.table = getSelectedTables();
    state.filters.exporter = getSelectedExporters();
    state.filters.proto = getSelectedProtocols();

    // Read current inputs in condition builder into state.filters.conditions
    const container = document.getElementById('flow-conditions-list');
    if (container) {
        const rows = container.querySelectorAll('.condition-row');
        const conds = [];
        rows.forEach(row => {
            const fieldEl = row.querySelector('.cond-field');
            const ipTypeEl = row.querySelector('.cond-iptype');
            const valEl = row.querySelector('.cond-val');
            if (fieldEl) {
                const field = fieldEl.value;
                const ipType = ipTypeEl ? ipTypeEl.value : 'custom';
                let val = valEl ? valEl.value.trim() : '';
                if (['src_ip', 'dst_ip', 'any_ip'].includes(field) && ipType !== 'custom') {
                    val = ipType;
                }
                conds.push({
                    id: row.getAttribute('data-id') || genConditionId(),
                    field: field,
                    ipType: ipType,
                    val: val
                });
            }
        });
        state.filters.conditions = conds;
    }
}

// Read anomalies form elements into state anomalies filters
function applyAnomaliesFiltersFromForm() {
    const flagEl = document.getElementById('filter-anomalies-flag');
    if (flagEl) state.anomaliesFilters.flag = flagEl.value.trim();

    const container = document.getElementById('anomalies-conditions-list');
    if (container) {
        const rows = container.querySelectorAll('.condition-row');
        const conds = [];
        rows.forEach(row => {
            const fieldEl = row.querySelector('.cond-field');
            const ipTypeEl = row.querySelector('.cond-iptype');
            const valEl = row.querySelector('.cond-val');
            if (fieldEl) {
                const field = fieldEl.value;
                const ipType = ipTypeEl ? ipTypeEl.value : 'custom';
                let val = valEl ? valEl.value.trim() : '';
                if (['src_ip', 'dst_ip', 'any_ip'].includes(field) && ipType !== 'custom') {
                    val = ipType;
                }
                conds.push({
                    id: row.getAttribute('data-id') || genConditionId(),
                    field: field,
                    ipType: ipType,
                    val: val
                });
            }
        });
        state.anomaliesFilters.conditions = conds;
    }
}

// Helper: Format Bytes into human readable strings
function formatBytes(bytes) {
    if (bytes === 0 || bytes === null || bytes === undefined) return '0 Bytes';
    if (bytes < 1 && bytes > 0) return parseFloat(bytes.toFixed(2)) + ' Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(sizes.length - 1, Math.max(0, Math.floor(Math.log(bytes) / Math.log(k))));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper: Format integers
function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return new Intl.NumberFormat().format(num);
}

// Fetch Exporters to populate filter dropdown
async function fetchExporterDropdown(skipRefresh = false) {
    try {
        const res = await fetch('/api/exporters');
        if (!res.ok) throw new Error('Failed to fetch exporters list');
        const exporters = await res.json();
        
        const container = document.getElementById('filter-exporter-group');
        if (container) {
            const prevCheckboxes = container.querySelectorAll('input[type="checkbox"]');
            const prevChecked = new Set();
            let allWereChecked = true;
            if (prevCheckboxes.length > 0) {
                prevCheckboxes.forEach(cb => {
                    if (cb.checked) prevChecked.add(cb.value);
                    else allWereChecked = false;
                });
            }

            container.innerHTML = '';
            exporters.forEach(ip => {
                const label = document.createElement('label');
                label.className = 'checkbox-label';
                const isChecked = allWereChecked || prevChecked.has(ip);
                label.innerHTML = `<input type="checkbox" name="exporter" value="${ip}" ${isChecked ? 'checked' : ''}> ${ip}`;
                container.appendChild(label);
            });
            
            // Register change event listener on new checkboxes to update trigger label
            container.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.addEventListener('change', updateDropdownLabels);
            });
            updateDropdownLabels();
            
            if (!skipRefresh) {
                refreshData();
            }
        }
    } catch (err) {
        console.error('Error fetching exporters dropdown:', err);
    }
}

// Helper to update KPI DOM elements from stats payload
function updateKpiDom(data) {
    if (!data) return;
    if (els.kpiTotalFlows) els.kpiTotalFlows.innerText = formatNumber(data.total_flows);
    if (els.kpiTotalBytes) els.kpiTotalBytes.innerText = formatBytes(data.total_bytes);
    if (els.kpiTotalPackets) els.kpiTotalPackets.innerText = formatNumber(data.total_packets);
    if (els.kpiTotalExporters && Array.isArray(data.top_exporters)) {
        els.kpiTotalExporters.innerText = formatNumber(data.top_exporters.length);
    }
}

// Refresh active tab and KPI totals
async function refreshData() {
    applyFiltersFromForm();
    if (state.activeTab === 'explorer') {
        await Promise.all([fetchKPIs(), fetchFlows()]);
    } else if (state.activeTab === 'analytics') {
        await fetchStats();
    } else if (state.activeTab === 'anomalies') {
        if (diagState.mode === 'smart') {
            await fetchSmartDiagnostics();
        } else {
            await Promise.all([fetchAnomalousReport(), fetchAnomalousReportStats()]);
        }
    }
}

// Fetch general totals for KPIs
async function fetchKPIs() {
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange
    });
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.ip) params.append('ip', state.filters.ip);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.port) params.append('port', state.filters.port);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    // Dynamic conditions
    if (state.filters.conditions && state.filters.conditions.length > 0) {
        const validConds = state.filters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            params.append('conditions', JSON.stringify(validConds));
            params.append('logic', state.filters.logic || 'AND');
        }
    }

    try {
        const signal = getAbortSignal('stats');
        const res = await fetch(`/api/stats?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('Failed to fetch KPI stats');
        const data = await res.json();
        updateKpiDom(data);
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Error fetching KPIs:', err);
    }
}

// Build URL query parameters from current filter and sort state
function getFlowQueryParams() {
    const activeCols = getActiveColumns();
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange,
        sort_by: state.sorting.by,
        sort_order: state.sorting.order,
        group_by: activeCols.join(',')
    });
    
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.ip) params.append('ip', state.filters.ip);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.port) params.append('port', state.filters.port);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    // Dynamic conditions
    if (state.filters.conditions && state.filters.conditions.length > 0) {
        const validConds = state.filters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            params.append('conditions', JSON.stringify(validConds));
            params.append('logic', state.filters.logic || 'AND');
        }
    }

    return params;
}

// Fetch flows list for table
async function fetchFlows() {
    const activeCols = getActiveColumns();
    const visibleColsCount = activeCols.length + 2; // +2 for packets and octets
    
    els.flowsTbody.innerHTML = `
        <tr>
            <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                <div class="spinner"></div>
                正在載入流量記錄...
            </td>
        </tr>
    `;
    
    const params = getFlowQueryParams();
    params.append('limit', state.pagination.limit);
    params.append('offset', state.pagination.offset);
    
    try {
        const signal = getAbortSignal('flows');
        const res = await fetch(`/api/flows?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('查詢流量記錄失敗');
        const data = await res.json();
        
        state.records = data.records;
        state.pagination.total = data.total;
        
        renderFlowsTable();
        renderPagination();
    } catch (err) {
        if (err.name === 'AbortError') return;
        els.flowsTbody.innerHTML = `
            <tr>
                <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                    <span style="color: var(--color-danger)">載入流量記錄失敗: ${err.message}</span>
                </td>
            </tr>
        `;
        console.error('Error fetching flows:', err);
    }
}

// Render the flows table rows
function renderFlowsTable() {
    const activeCols = getActiveColumns();
    const visibleColsCount = activeCols.length + 2;

    if (state.records.length === 0) {
        els.flowsTbody.innerHTML = `
            <tr>
                <td colspan="${visibleColsCount}" class="text-center text-muted py-5">
                    查無符合條件之流量記錄。請確認流量收集器已啟動並正常接收流量。
                </td>
            </tr>
        `;
        els.flowRangeStart.innerText = '0';
        els.flowRangeEnd.innerText = '0';
        els.flowTotalFiltered.innerText = '0';
        return;
    }
    
    els.flowsTbody.innerHTML = '';
    state.records.forEach((r, idx) => {
        const tr = document.createElement('tr');
        tr.addEventListener('click', () => showFlowDetails(idx));
        
        // Table values mapping
        const badgeType = r.type === 'ipfix' ? 'badge-info' : (r.type === 'netflow9' ? 'badge-primary' : 'badge-warning');
        const typeLabel = r.type ? r.type.toUpperCase() : '已聚合';
        
        const timeFormatted = r.ts ? formatSqlTimestamp(r.ts) : '已聚合';
        const protocolText = r.proto_name || '已聚合';
        
        tr.innerHTML = `
            <td class="col-type"><span class="badge ${badgeType}">${typeLabel}</span></td>
            <td class="col-ts">${timeFormatted}</td>
            <td class="col-exporter">${r.exporter || '-'}</td>
            <td class="col-src">
                <strong>${r.src || '-'}</strong>
                ${r.src_domain ? `<div class="domain-subtext" title="${r.src_domain}">${r.src_domain}</div>` : ''}
            </td>
            <td class="col-sport">
                <span class="text-secondary">${r.sport !== null && r.sport !== undefined ? r.sport : '-'}</span>
                ${r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : ''}
            </td>
            <td class="col-dst">
                <strong>${r.dst || '-'}</strong>
                ${r.dst_domain ? `<div class="domain-subtext" title="${r.dst_domain}">${r.dst_domain}</div>` : ''}
            </td>
            <td class="col-dport">
                <span class="text-secondary">${r.dport !== null && r.dport !== undefined ? r.dport : '-'}</span>
                ${r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : ''}
            </td>
            <td class="col-proto"><span class="badge badge-success">${protocolText}</span></td>
            <td class="col-packets">${formatNumber(r.packets)}</td>
            <td class="col-octets"><strong>${formatBytes(r.octets)}</strong></td>
        `;
        els.flowsTbody.appendChild(tr);
    });
    
    // Apply layout toggles
    applyColumnVisibility();

    // Update pagination stats
    const start = state.pagination.offset + 1;
    const end = Math.min(state.pagination.offset + state.records.length, state.pagination.total);
    els.flowRangeStart.innerText = formatNumber(start);
    els.flowRangeEnd.innerText = formatNumber(end);
    els.flowTotalFiltered.innerText = formatNumber(state.pagination.total);
    
    // Create lucide icons inside rows
    lucide.createIcons();
}

// Render dynamic pagination buttons
function renderPagination() {
    const container = els.flowsPagination;
    container.innerHTML = '';
    
    const limit = state.pagination.limit;
    const offset = state.pagination.offset;
    const total = state.pagination.total;
    
    const totalPages = Math.ceil(total / limit);
    const currentPage = Math.floor(offset / limit) + 1;
    
    if (totalPages <= 1) return;
    
    // Prev Button
    const prevBtn = document.createElement('div');
    prevBtn.className = `pagination-btn ${currentPage === 1 ? 'disabled' : ''}`;
    prevBtn.innerHTML = '<i data-lucide="chevron-left" style="width: 14px; height: 14px"></i>';
    if (currentPage > 1) {
        prevBtn.addEventListener('click', () => {
            state.pagination.offset = (currentPage - 2) * limit;
            fetchFlows();
        });
    }
    container.appendChild(prevBtn);
    
    // Page Numbers (Show max 5 pages, with ellipses)
    let startPage = Math.max(1, currentPage - 2);
    let endPage = Math.min(totalPages, startPage + 4);
    if (endPage - startPage < 4) {
        startPage = Math.max(1, endPage - 4);
    }
    
    for (let p = startPage; p <= endPage; p++) {
        const btn = document.createElement('div');
        btn.className = `pagination-btn ${p === currentPage ? 'active' : ''}`;
        btn.innerText = p;
        btn.addEventListener('click', () => {
            if (p !== currentPage) {
                state.pagination.offset = (p - 1) * limit;
                fetchFlows();
            }
        });
        container.appendChild(btn);
    }
    
    // Next Button
    const nextBtn = document.createElement('div');
    nextBtn.className = `pagination-btn ${currentPage === totalPages ? 'disabled' : ''}`;
    nextBtn.innerHTML = '<i data-lucide="chevron-right" style="width: 14px; height: 14px"></i>';
    if (currentPage < totalPages) {
        nextBtn.addEventListener('click', () => {
            state.pagination.offset = currentPage * limit;
            fetchFlows();
        });
    }
    container.appendChild(nextBtn);
    
    // Re-create icons for pagination chevrons
    lucide.createIcons();
}

// Standard Taiwan time (Asia/Taipei UTC+8) formatter
function formatSqlTimestamp(tsString) {
    if (!tsString) return '';
    return String(tsString).replace('T', ' ').replace('Z', '').substring(0, 19);
}

// Show modal dialog containing complete details of clicked row
function showFlowDetails(idx) {
    const r = state.records[idx];
    if (!r) return;
    
    if (els.detailRuleSection) {
        els.detailRuleSection.style.display = 'none';
    }
    
    els.detailId.innerText = r.id || '不適用 (聚合資料)';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : '已聚合';
    els.detailType.innerText = r.type ? r.type.toUpperCase() : '已聚合';
    els.detailType.className = `value badge ${r.type === 'ipfix' ? 'badge-info' : (r.type === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    els.detailExporter.innerText = r.exporter || '已聚合';
    els.detailSrc.innerText = r.src || '已聚合';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || '已聚合';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || '已聚合';
    els.detailOctets.innerText = `${formatNumber(r.octets)} 位元組 (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Render raw json formatted
    const raw = r.raw_details || {};
    els.detailRawJson.innerText = JSON.stringify(raw, null, 2);
    
    els.detailsModal.classList.add('active');
}

function closeModal() {
    els.detailsModal.classList.remove('active');
}

// Helper to format IP labels with domains in charts
function formatChartIPLabel(ip, domain) {
    if (!domain) return ip;
    const maxDomainLen = 18;
    const displayDomain = domain.length > maxDomainLen ? domain.substring(0, maxDomainLen) + '...' : domain;
    return `${ip} (${displayDomain})`;
}

// Helper to format Alias labels in charts (truncate long names to keep chart heights consistent)
function formatChartAliasLabel(name) {
    if (!name) return '';
    const maxLen = 18;
    return name.length > maxLen ? name.substring(0, maxLen) + '...' : name;
}

// Fetch stats and render analytics charts
async function fetchStats() {
    const params = new URLSearchParams({
        table: state.filters.table,
        time_range: state.filters.timeRange
    });
    if (state.filters.exporter) params.append('exporter', state.filters.exporter);
    if (state.filters.ip) params.append('ip', state.filters.ip);
    if (state.filters.src) params.append('src', state.filters.src);
    if (state.filters.dst) params.append('dst', state.filters.dst);
    if (state.filters.port) params.append('port', state.filters.port);
    if (state.filters.sport) params.append('sport', state.filters.sport);
    if (state.filters.dport) params.append('dport', state.filters.dport);
    if (state.filters.proto) params.append('proto', state.filters.proto);
    if (state.filters.startTime) params.append('start_time', state.filters.startTime);
    if (state.filters.endTime) params.append('end_time', state.filters.endTime);

    // Dynamic conditions
    if (state.filters.conditions && state.filters.conditions.length > 0) {
        const validConds = state.filters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            params.append('conditions', JSON.stringify(validConds));
            params.append('logic', state.filters.logic || 'AND');
        }
    }

    try {
        const signal = getAbortSignal('stats');
        const res = await fetch(`/api/stats?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('Failed to fetch statistics');
        const data = await res.json();
        
        updateKpiDom(data);
        renderTimeChart(data.traffic_over_time);
        renderBarChart(
            'chart-top-sources', 
            'Top Sources', 
            data.top_sources.map(x => formatChartIPLabel(x.src, x.domain)), 
            data.top_sources.map(x => x.bytes),
            { itemType: 'ip', defaultDir: 'src', viewType: 'general', rawItems: data.top_sources.map(x => x.src) }
        );
        renderBarChart(
            'chart-top-destinations', 
            'Top Destinations', 
            data.top_destinations.map(x => formatChartIPLabel(x.dst, x.domain)), 
            data.top_destinations.map(x => x.bytes),
            { itemType: 'ip', defaultDir: 'dst', viewType: 'general', rawItems: data.top_destinations.map(x => x.dst) }
        );
        renderBarChart(
            'chart-top-src-ports', 
            'Top 10 Source Ports', 
            data.top_source_ports.map(x => x.sport.toString() + (x.port_name ? ` (${x.port_name})` : '')), 
            data.top_source_ports.map(x => x.bytes),
            { itemType: 'port', defaultDir: 'src', viewType: 'general', rawItems: data.top_source_ports.map(x => x.sport) }
        );
        renderBarChart(
            'chart-top-dst-ports', 
            'Top 10 Destination Ports', 
            data.top_destination_ports.map(x => x.dport.toString() + (x.port_name ? ` (${x.port_name})` : '')), 
            data.top_destination_ports.map(x => x.bytes),
            { itemType: 'port', defaultDir: 'dst', viewType: 'general', rawItems: data.top_destination_ports.map(x => x.dport) }
        );
        const topAliases = data.top_aliases || [];
        renderBarChart(
            'chart-top-aliases',
            '前十大 IP 別名',
            topAliases.map(x => formatChartAliasLabel(x.name)),
            topAliases.map(x => x.bytes),
            { 
                itemType: 'alias', 
                defaultDir: 'any', 
                viewType: 'general', 
                rawItems: topAliases.map(x => x.name),
                flowCounts: topAliases.map(x => x.flows)
            }
        );
        renderDoughnutChart('chart-exporters', data.top_exporters.map(x => x.exporter), data.top_exporters.map(x => x.flows));
        
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Error fetching stats:', err);
    }
}

// Chart renderers
function renderTimeChart(timeData) {
    const canvasId = 'chart-traffic-time';
    destroyChart(canvasId);
    
    const ctx = document.getElementById(canvasId).getContext('2d');
    
    const labels = timeData.map(x => {
        // format label according to time bin
        const bin = x.time_bin;
        if (!bin) return '';
        // E.g. "2026-07-03 14:00:00" -> "14:00"
        if (bin.length > 13) return bin.substring(11, 16);
        return bin;
    });
    
    const bytesData = timeData.map(x => x.bytes);
    const packetsData = timeData.map(x => x.packets);
    
    state.charts[canvasId] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: '傳輸量 (Bytes)',
                    data: bytesData,
                    borderColor: '#6366f1',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    yAxisID: 'y-bytes',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2
                },
                {
                    label: '封包數',
                    data: packetsData,
                    borderColor: '#10b981',
                    backgroundColor: 'transparent',
                    yAxisID: 'y-packets',
                    fill: false,
                    tension: 0.3,
                    borderWidth: 2,
                    borderDash: [5, 5]
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    labels: { color: '#9ca3af' }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.datasetIndex === 0) {
                                label += formatBytes(context.parsed.y);
                            } else {
                                label += formatNumber(context.parsed.y);
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#9ca3af' }
                },
                'y-bytes': {
                    type: 'linear',
                    position: 'left',
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                },
                'y-packets': {
                    type: 'linear',
                    position: 'right',
                    grid: { drawOnChartArea: false }, // avoid grid overlap
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatNumber(value);
                        }
                    }
                }
            }
        }
    });
}

function renderBarChart(canvasId, title, labels, data, drillMeta) {
    destroyChart(canvasId);
    
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const ctx2d = ctx.getContext('2d');
    
    const ds = {
        label: '傳輸量 (Bytes)',
        data: data,
        backgroundColor: 'rgba(99, 102, 241, 0.75)',
        borderColor: '#6366f1',
        borderWidth: 1,
        borderRadius: 4
    };
    if (drillMeta) {
        ds.drillMeta = drillMeta;
    }

    state.charts[canvasId] = new Chart(ctx2d, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [ds]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (event, elements, chart) => {
                if (!elements || elements.length === 0) return;
                const index = elements[0].index;
                const meta = chart.data.datasets[0].drillMeta;
                if (!meta) return;
                const rawVal = (meta.rawItems && meta.rawItems[index] !== undefined) ? meta.rawItems[index] : chart.data.labels[index];
                showChartContextMenu(event.native || event, meta.itemType, rawVal, meta.viewType, meta.defaultDir);
            },
            onHover: (event, chartElement) => {
                const target = event.native ? event.native.target : (event.target || (event.chart && event.chart.canvas));
                if (target) {
                    target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            if (!context || !context.length) return '';
                            const meta = context[0].chart.data.datasets[0].drillMeta;
                            if (meta && meta.itemType === 'alias' && meta.rawItems && meta.rawItems[context[0].dataIndex] !== undefined) {
                                return meta.rawItems[context[0].dataIndex];
                            }
                            return context[0].label;
                        },
                        label: function(context) {
                            let label = '傳輸量: ' + formatBytes(context.parsed.y);
                            const meta = context.chart.data.datasets[0].drillMeta;
                            if (meta && meta.flowCounts && meta.flowCounts[context.dataIndex] !== undefined) {
                                label += ` (${formatNumber(meta.flowCounts[context.dataIndex])} flows)`;
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#9ca3af',
                        maxRotation: 45,
                        minRotation: 0
                    }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

function renderDoughnutChart(canvasId, labels, data, drillMeta) {
    destroyChart(canvasId);
    if (labels.length === 0) return; // avoid empty doughnut bug
    
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const ctx2d = ctx.getContext('2d');

    const ds = {
        data: data,
        backgroundColor: [
            '#6366f1', // Indigo
            '#10b981', // Emerald
            '#0ea5e9', // Sky Blue
            '#f59e0b', // Amber
            '#ef4444', // Rose Red
            '#8b5cf6', // Purple
            '#ec4899', // Pink
        ],
        borderWidth: 1,
        borderColor: '#111827'
    };
    if (drillMeta) {
        ds.drillMeta = drillMeta;
    }

    state.charts[canvasId] = new Chart(ctx2d, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [ds]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (event, elements, chart) => {
                if (!elements || elements.length === 0) return;
                const index = elements[0].index;
                const meta = chart.data.datasets[0].drillMeta;
                if (!meta) return;
                const rawVal = (meta.rawItems && meta.rawItems[index] !== undefined) ? meta.rawItems[index] : chart.data.labels[index];
                showChartContextMenu(event.native || event, meta.itemType, rawVal, meta.viewType, meta.defaultDir);
            },
            onHover: (event, chartElement) => {
                const target = event.native ? event.native.target : (event.target || (event.chart && event.chart.canvas));
                if (target) {
                    target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            },
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9ca3af',
                        font: { size: 11 }
                    }
                }
            }
        }
    });
}

// Clean up chart instance if it exists to allow rendering new data without bugs
function destroyChart(canvasId) {
    if (state.charts[canvasId]) {
        state.charts[canvasId].destroy();
        delete state.charts[canvasId];
    }
}

// Setup Header Sorting click listeners
function setupHeaderSorting() {
    const headers = document.querySelectorAll('#flows-table th.sortable');
    headers.forEach(th => {
        th.addEventListener('click', () => {
            const sortBy = th.getAttribute('data-sort');
            if (state.sorting.by === sortBy) {
                // Toggle order
                state.sorting.order = state.sorting.order === 'asc' ? 'desc' : 'asc';
            } else {
                state.sorting.by = sortBy;
                state.sorting.order = 'desc'; // Default to desc for new fields
            }
            updateHeaderSortIcons();
            state.pagination.offset = 0; // Reset pagination
            fetchFlows();
        });
    });
}

// Update header sorting icons state
function updateHeaderSortIcons() {
    const headers = document.querySelectorAll('#flows-table th.sortable');
    headers.forEach(th => {
        const sortBy = th.getAttribute('data-sort');
        const icon = th.querySelector('.sort-icon');
        if (icon) {
            if (sortBy === state.sorting.by) {
                th.classList.add('sort-active');
                if (state.sorting.order === 'asc') {
                    icon.setAttribute('data-lucide', 'chevron-up');
                } else {
                    icon.setAttribute('data-lucide', 'chevron-down');
                }
            } else {
                th.classList.remove('sort-active');
                icon.setAttribute('data-lucide', 'chevrons-up-down');
            }
        }
    });
    // Re-initialize Lucide Icons so they re-render the new icon types
    lucide.createIcons();
}

// Setup Audit Tables Header Sorting click listeners
function setupAuditHeaderSorting() {
    const headers = document.querySelectorAll('#anomalies-table th.sortable, #audit-matches-table th.sortable');
    headers.forEach(th => {
        th.addEventListener('click', () => {
            const sortBy = th.getAttribute('data-sort');
            if (state.auditSorting.by === sortBy) {
                state.auditSorting.order = state.auditSorting.order === 'asc' ? 'desc' : 'asc';
            } else {
                state.auditSorting.by = sortBy;
                state.auditSorting.order = 'desc';
            }
            updateAuditHeaderSortIcons();
            
            // Reset pagination offsets
            state.auditPagination.offset = 0;
            state.anomaliesPagination.offset = 0;
            
            // Fetch matches & anomalies report
            fetchAuditMatches();
            fetchAnomalousReport();
        });
    });
}

// Update audit tables header sorting icons state
function updateAuditHeaderSortIcons() {
    const headers = document.querySelectorAll('#anomalies-table th.sortable, #audit-matches-table th.sortable');
    headers.forEach(th => {
        const sortBy = th.getAttribute('data-sort');
        const icon = th.querySelector('.sort-icon');
        if (icon) {
            if (sortBy === state.auditSorting.by) {
                th.classList.add('sort-active');
                if (state.auditSorting.order === 'asc') {
                    icon.setAttribute('data-lucide', 'chevron-up');
                } else {
                    icon.setAttribute('data-lucide', 'chevron-down');
                }
            } else {
                th.classList.remove('sort-active');
                icon.setAttribute('data-lucide', 'chevrons-up-down');
            }
        }
    });
    lucide.createIcons();
}

// Read checkbox-group to build comma-separated protocol string
function getSelectedProtocols() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#filter-proto-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked.join(',');
}

// Read checked columns visibility list
function getActiveColumns() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked;
}

// Setup Column display toggles change listener
function setupColumnToggles() {
    const toggles = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    toggles.forEach(toggle => {
        toggle.addEventListener('change', () => {
            state.pagination.offset = 0; // Reset pagination
            fetchFlows();
        });
    });
}

// Apply table columns visibility hide/show classes dynamically
function applyColumnVisibility() {
    const toggles = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    toggles.forEach(toggle => {
        const colName = toggle.value;
        const visible = toggle.checked;
        const cells = document.querySelectorAll(`.col-${colName}`);
        cells.forEach(cell => {
            cell.style.display = visible ? '' : 'none';
        });
    });
    
    // Sync loading/empty message colspans
    const activeCols = getActiveColumns();
    const visibleCount = activeCols.length + 2; // Add Packets and Bytes
    const colspans = document.querySelectorAll('#flows-tbody td[colspan]');
    colspans.forEach(cell => {
        cell.setAttribute('colspan', visibleCount);
    });
}

// Toggle custom dropdowns open state
function setupDropdowns() {
    const dropdowns = document.querySelectorAll('.custom-dropdown');
    
    dropdowns.forEach(dd => {
        const trigger = dd.querySelector('.dropdown-trigger');
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            
            // Close other dropdowns
            dropdowns.forEach(other => {
                if (other !== dd) {
                    other.classList.remove('open');
                }
            });
            
            dd.classList.toggle('open');
        });
        
        // Prevent clicks inside panel from closing dropdown
        const panel = dd.querySelector('.dropdown-menu-panel');
        panel.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    });
    
    // Clicking outside closes all dropdowns
    document.addEventListener('click', () => {
        dropdowns.forEach(dd => {
            dd.classList.remove('open');
        });
    });
    
    // Register update listeners on checkboxes
    const checkboxes = document.querySelectorAll('.custom-dropdown input[type="checkbox"]');
    checkboxes.forEach(cb => {
        cb.addEventListener('change', updateDropdownLabels);
    });
    
    // Initial label render
    updateDropdownLabels();
}

// Sync label texts on dropdown triggers
function updateDropdownLabels() {
    // Update Protocols Label
    const checkedProtos = [];
    const protoCheckboxes = document.querySelectorAll('#filter-proto-group input[type="checkbox"]');
    protoCheckboxes.forEach(cb => {
        if (cb.checked) checkedProtos.push(cb.value);
    });
    const labelProto = document.getElementById('label-proto');
    if (labelProto) {
        if (checkedProtos.length === 0) {
            labelProto.innerText = '無';
        } else if (checkedProtos.length === protoCheckboxes.length) {
            labelProto.innerText = '所有協定';
        } else {
            labelProto.innerText = checkedProtos.join(', ');
        }
    }
    
    // Update Data Source Label
    const checkedTables = [];
    const tableCheckboxes = document.querySelectorAll('#filter-table-group input[type="checkbox"]');
    tableCheckboxes.forEach(cb => {
        if (cb.checked) {
            checkedTables.push(cb.parentNode.textContent.trim());
        }
    });
    const labelTable = document.getElementById('label-table');
    if (labelTable) {
        if (checkedTables.length === 0) {
            labelTable.innerText = '無';
        } else if (checkedTables.length === tableCheckboxes.length) {
            labelTable.innerText = '所有資料來源';
        } else {
            labelTable.innerText = checkedTables.join(', ');
        }
    }

    // Update Exporter IP Label
    const checkedExporters = [];
    const exporterCheckboxes = document.querySelectorAll('#filter-exporter-group input[type="checkbox"]');
    exporterCheckboxes.forEach(cb => {
        if (cb.checked) {
            checkedExporters.push(cb.value);
        }
    });
    const labelExporter = document.getElementById('label-exporter');
    if (labelExporter) {
        if (checkedExporters.length === 0) {
            labelExporter.innerText = '無';
        } else if (checkedExporters.length === exporterCheckboxes.length) {
            labelExporter.innerText = '所有 Exporter';
        } else {
            labelExporter.innerText = checkedExporters.length > 2 
                ? `${checkedExporters.length} 個 Exporter` 
                : checkedExporters.join(', ');
        }
    }
    
    // Update Columns Label
    const checkedCols = [];
    const colCheckboxes = document.querySelectorAll('#column-toggles input[type="checkbox"]');
    colCheckboxes.forEach(cb => {
        if (cb.checked) {
            checkedCols.push(cb.parentNode.textContent.trim());
        }
    });
    const labelCols = document.getElementById('label-columns');
    if (labelCols) {
        if (checkedCols.length === 0) {
            labelCols.innerText = '無';
        } else if (checkedCols.length === colCheckboxes.length) {
            labelCols.innerText = '所有欄位';
        } else {
            labelCols.innerText = `${checkedCols.length} 個欄位`;
        }
    }
}

function getSelectedTables() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#filter-table-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    return checked.join(',');
}

function getSelectedExporters() {
    const checked = [];
    const checkboxes = document.querySelectorAll('#filter-exporter-group input[type="checkbox"]');
    checkboxes.forEach(cb => {
        if (cb.checked) {
            checked.push(cb.value);
        }
    });
    // If all or none are checked, treat as All Exporters (no filter restriction)
    if (checked.length === checkboxes.length || checked.length === 0) {
        return '';
    }
    return checked.join(',');
}

// Convert local datetime-local string input value to Taiwan time format YYYY-MM-DD HH:MM:SS
function toTaiwanLocalTimestamp(localStr) {
    if (!localStr) return '';
    let clean = localStr.replace('T', ' ').trim();
    if (clean.length === 16) clean += ':00';
    return clean;
}

// Execute Manual Data Cleanup API POST Request
async function executeCleanup() {
    const beforeVal = els.cleanupBeforeDate.value;
    if (!beforeVal) {
        showCleanupStatus('請選擇日期與時間。', 'error');
        return;
    }
    
    const localDate = toTaiwanLocalTimestamp(beforeVal);
    if (!localDate) {
        showCleanupStatus('所選日期格式無效。', 'error');
        return;
    }
    
    if (!confirm(`您確定要刪除所有在 ${localDate} (台灣時間) 之前的流量資料嗎？此操作將無法復原。`)) {
        return;
    }
    
    showCleanupStatus('正在執行資料清理...', 'info');
    els.btnExecuteCleanup.disabled = true;
    
    try {
        const response = await fetch(`/api/flows/delete?before=${encodeURIComponent(localDate)}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        if (response.ok) {
            showCleanupStatus(data.message || '資料清理已成功發起。', 'success');
            els.cleanupBeforeDate.value = ''; // Reset input
            fetchRetentionSettings(); // Refresh retention card status
        } else {
            showCleanupStatus(data.detail || '發起資料清理失敗。', 'error');
        }
    } catch (err) {
        showCleanupStatus(`網路錯誤: ${err.message}`, 'error');
    } finally {
        els.btnExecuteCleanup.disabled = false;
    }
}

function showCleanupStatus(message, type) {
    const el = els.cleanupStatusMessage;
    el.style.display = 'block';
    el.innerText = message;
    
    // Reset background and borders
    el.style.backgroundColor = '';
    el.style.color = '';
    el.style.border = '';
    
    if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else { // info
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }
}

// Fetch and render Port Aliases
async function fetchPortAliases() {
    const tbody = document.getElementById('port-aliases-tbody');
    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td colspan="3" class="text-center text-muted py-3">正在載入別名...</td>
        </tr>
    `;

    try {
        const res = await fetch('/api/ports/aliases');
        if (!res.ok) throw new Error('Failed to fetch port aliases');
        const list = await res.json();
        
        renderPortAliasesTable(list);
    } catch (err) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">
                    <span style="color: var(--color-danger);">Error: ${err.message}</span>
                </td>
            </tr>
        `;
    }
}

// Render the Port Aliases table rows
function renderPortAliasesTable(list) {
    const tbody = document.getElementById('port-aliases-tbody');
    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">尚未設定任何自訂 Port 別名。</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = '';
    list.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="padding: 8px 12px; color: var(--text-primary); font-weight: 500; width: 35%;">${item.port}</td>
            <td class="name-cell" style="padding: 8px 12px; color: var(--text-secondary); width: 45%;">${item.name}</td>
            <td class="actions-cell" style="padding: 8px 12px; text-align: right; width: 20%;">
                <button class="btn-edit-alias" style="background: none; border: none; color: var(--color-primary); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="edit-2" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-delete-alias" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
                </button>
            </td>
        `;
        
        const nameCell = tr.querySelector('.name-cell');
        const actionsCell = tr.querySelector('.actions-cell');
        const btnEdit = tr.querySelector('.btn-edit-alias');
        const btnDelete = tr.querySelector('.btn-delete-alias');
        
        // Bind edit action (inline edit)
        btnEdit.addEventListener('click', () => {
            nameCell.innerHTML = `<input type="text" class="form-control select-dark edit-name-input" style="width: 100%; background: rgba(0, 0, 0, 0.2); border: 1px solid var(--border-color); border-radius: 4px; padding: 4px 8px; color: var(--text-primary); font-size: 0.85rem;" value="${item.name.replace(/"/g, '&quot;')}">`;
            
            actionsCell.innerHTML = `
                <button class="btn-save-edit" style="background: none; border: none; color: var(--color-success); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="check" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-cancel-edit" style="background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="x" style="width: 14px; height: 14px;"></i>
                </button>
            `;
            
            if (window.lucide && typeof window.lucide.createIcons === 'function') {
                window.lucide.createIcons();
            }
            
            const saveBtn = actionsCell.querySelector('.btn-save-edit');
            const cancelBtn = actionsCell.querySelector('.btn-cancel-edit');
            const editInput = nameCell.querySelector('.edit-name-input');
            
            editInput.focus();
            
            saveBtn.addEventListener('click', async () => {
                const newName = editInput.value.trim();
                if (!newName) {
                    showPortAliasStatus('別名名稱不得為空', 'error');
                    return;
                }
                
                try {
                    const res = await fetch(`/api/ports/aliases?port=${item.port}&name=${encodeURIComponent(newName)}`, { method: 'POST' });
                    if (!res.ok) throw new Error('Save request failed');
                    showPortAliasStatus('Port 別名已成功更新', 'success');
                    fetchPortAliases();
                    fetchFlows();
                } catch (err) {
                    showPortAliasStatus(`儲存失敗: ${err.message}`, 'error');
                }
            });
            
            cancelBtn.addEventListener('click', () => {
                renderPortAliasesTable(list);
            });
            
            editInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    saveBtn.click();
                } else if (e.key === 'Escape') {
                    cancelBtn.click();
                }
            });
        });
        
        // Bind delete action
        btnDelete.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm(`您確定要刪除 Port ${item.port} 的別名嗎？`)) return;
            
            try {
                const res = await fetch(`/api/ports/aliases/${item.port}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                showPortAliasStatus('別名已成功刪除', 'success');
                fetchPortAliases();
                fetchFlows();
            } catch (err) {
                showPortAliasStatus(`刪除失敗: ${err.message}`, 'error');
            }
        });
        
        tbody.appendChild(tr);
    });

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

// Save/Update Port Alias handler
async function handleSavePortAlias(e) {
    e.preventDefault();
    const inputPort = document.getElementById('input-alias-port');
    const inputName = document.getElementById('input-alias-name');
    if (!inputPort || !inputName) return;

    const port = parseInt(inputPort.value);
    const name = inputName.value.trim();

    if (!port || !name) {
        showPortAliasStatus('請填寫 Port 埠號與別名名稱。', 'error');
        return;
    }

    try {
        const res = await fetch(`/api/ports/aliases?port=${port}&name=${encodeURIComponent(name)}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to save port alias');
        
        showPortAliasStatus(`已成功將 Port ${port} 對應為 ${name}`, 'success');
        inputPort.value = '';
        inputName.value = '';
        fetchPortAliases();
        // Refresh flows table to reflect names update immediately
        fetchFlows();
    } catch (err) {
        showPortAliasStatus(`儲存失敗: ${err.message}`, 'error');
    }
}

// Show status message for Port Alias form
function showPortAliasStatus(message, type) {
    const el = document.getElementById('port-alias-status-message');
    if (!el) return;

    el.style.display = 'block';
    el.innerText = message;
    el.style.backgroundColor = '';
    el.style.color = '';
    el.style.border = '';

    if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }

    // Auto hide after 4 seconds
    setTimeout(() => {
        el.style.display = 'none';
    }, 4000);
}

// Fetch and render IP Aliases
async function fetchIpAliases() {
    const tbody = document.getElementById('ip-aliases-tbody');
    if (!tbody) return;

    tbody.innerHTML = `
        <tr>
            <td colspan="3" class="text-center text-muted py-3">正在載入 IP 別名...</td>
        </tr>
    `;

    const limit = state.ipAliasesPagination.limit;
    const offset = state.ipAliasesPagination.offset;
    const q = state.ipAliasesPagination.search;
    
    let url = `/api/ips/aliases?limit=${limit}&offset=${offset}`;
    if (q) {
        url += `&q=${encodeURIComponent(q)}`;
    }

    try {
        const signal = getAbortSignal('ipAliases');
        const res = await fetch(url, { signal });
        if (!res.ok) throw new Error('Failed to fetch IP aliases');
        const data = await res.json();
        
        state.ipAliasesPagination.total = data.total;
        
        renderIpAliasesTable(data.records);
        renderIpAliasesPagination(data.total);
    } catch (err) {
        if (err.name === 'AbortError') return;
        tbody.innerHTML = `
            <tr>
                <td colspan="3" class="text-center text-muted py-3">
                    <span style="color: var(--color-danger);">Error: ${err.message}</span>
                </td>
            </tr>
        `;
    }
}

function renderIpAliasesPagination(total) {
    const info = document.getElementById('ip-aliases-pagination-info');
    const btnPrev = document.getElementById('btn-ip-aliases-prev');
    const btnNext = document.getElementById('btn-ip-aliases-next');
    if (!info || !btnPrev || !btnNext) return;
    
    const limit = state.ipAliasesPagination.limit;
    const offset = state.ipAliasesPagination.offset;
    
    const start = total === 0 ? 0 : offset + 1;
    const end = Math.min(total, offset + limit);
    
    info.innerText = `顯示第 ${start} 到 ${end} 筆，共 ${total} 筆`;
    
    btnPrev.disabled = (offset === 0);
    btnNext.disabled = (end >= total);
}

// Render the IP Aliases table rows
function renderIpAliasesTable(list) {
    const tbody = document.getElementById('ip-aliases-tbody');
    if (!tbody) return;

    if (list.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted py-3">尚未設定任何自訂 IP 別名。</td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = '';
    list.forEach(item => {
        const tr = document.createElement('tr');
        const ownerDept = [item.owner_name, item.department].filter(Boolean).map(escapeHtml).join(' · ') || '<span class="text-muted">-</span>';
        const vendorContact = [item.vendor_name, item.contact_info].filter(Boolean).map(escapeHtml).join(' · ') || '<span class="text-muted">-</span>';
        tr.innerHTML = `
            <td style="padding: 8px 12px; color: var(--text-primary); font-family: var(--font-mono); font-weight: 500;">${escapeHtml(item.ip)}</td>
            <td class="name-cell" style="padding: 8px 12px; color: var(--text-primary);">
                <div style="font-weight: 600;">${escapeHtml(item.name)}</div>
                ${item.device_role ? `<div style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(item.device_role)}</div>` : ''}
            </td>
            <td style="padding: 8px 12px; color: #fde68a; font-size: 0.82rem;">${ownerDept}</td>
            <td style="padding: 8px 12px; color: #34d399; font-size: 0.82rem;">${vendorContact}</td>
            <td class="actions-cell" style="padding: 8px 12px; text-align: right; white-space: nowrap;">
                <button class="btn-edit-ip-alias" title="帶入上方表單編輯" style="background: none; border: none; color: var(--color-primary); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s; margin-right: 6px;">
                    <i data-lucide="edit-2" style="width: 14px; height: 14px;"></i>
                </button>
                <button class="btn-delete-ip-alias" title="刪除" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                    <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
                </button>
            </td>
        `;
        
        const btnEdit = tr.querySelector('.btn-edit-ip-alias');
        const btnDelete = tr.querySelector('.btn-delete-ip-alias');
        
        btnEdit.addEventListener('click', () => {
            const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
            setVal('input-alias-ip', item.ip);
            setVal('input-alias-ip-name', item.name);
            setVal('input-alias-owner', item.owner_name);
            setVal('input-alias-dept', item.department);
            setVal('input-alias-vendor', item.vendor_name);
            setVal('input-alias-contact', item.contact_info);
            setVal('input-alias-role', item.device_role);
            document.getElementById('input-alias-ip-name')?.focus();
            showIpAliasStatus(`已將 ${item.ip} 帶入上方表單，修改後按「儲存」即可更新。`, 'success');
        });
        
        btnDelete.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!confirm(`您確定要刪除 IP ${item.ip} 的別名嗎？`)) return;
            
            try {
                const res = await fetch(`/api/ips/aliases/${encodeURIComponent(item.ip)}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                showIpAliasStatus('IP 別名已成功刪除', 'success');
                fetchIpAliases();
                fetchFlows();
            } catch (err) {
                showIpAliasStatus(`刪除失敗: ${err.message}`, 'error');
            }
        });
        
        tbody.appendChild(tr);
    });

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

// Save/Update IP Alias handler
async function handleSaveIpAlias(e) {
    e.preventDefault();
    const inputIp = document.getElementById('input-alias-ip');
    const inputName = document.getElementById('input-alias-ip-name');
    if (!inputIp || !inputName) return;

    const ip = inputIp.value.trim();
    const name = inputName.value.trim();
    const owner_name = (document.getElementById('input-alias-owner')?.value || '').trim();
    const department = (document.getElementById('input-alias-dept')?.value || '').trim();
    const vendor_name = (document.getElementById('input-alias-vendor')?.value || '').trim();
    const contact_info = (document.getElementById('input-alias-contact')?.value || '').trim();
    const device_role = (document.getElementById('input-alias-role')?.value || '').trim();

    if (!ip || !name) {
        showIpAliasStatus('請填寫 IP 位址與別名名稱。', 'error');
        return;
    }

    try {
        const params = new URLSearchParams({ ip, name, owner_name, department, vendor_name, contact_info, device_role });
        const res = await fetch(`/api/ips/aliases?${params.toString()}`, {
            method: 'POST'
        });
        if (!res.ok) throw new Error('Failed to save IP alias');
        
        showIpAliasStatus(`已成功儲存 IP ${ip} (${name}) 與負責人／廠商資訊`, 'success');
        ['input-alias-ip', 'input-alias-ip-name', 'input-alias-owner', 'input-alias-dept', 'input-alias-vendor', 'input-alias-contact', 'input-alias-role'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        fetchIpAliases();
        fetchFlows();
    } catch (err) {
        showIpAliasStatus(`儲存失敗: ${err.message}`, 'error');
    }
}

// Show status message for IP Alias form
function showIpAliasStatus(message, type) {
    const el = document.getElementById('ip-alias-status-message');
    if (!el) return;

    el.style.display = 'block';
    el.innerText = message;
    el.style.backgroundColor = '';
    el.style.color = '';
    el.style.border = '';

    if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }

    // Auto hide after 4 seconds
    setTimeout(() => {
        el.style.display = 'none';
    }, 4000);
}

// === Traffic Auditing Module ===

let currentAuditRules = [];

// Fetch all audit rules
async function fetchAuditRules() {
    try {
        const response = await fetch('/api/audit/rules');
        if (!response.ok) throw new Error('Failed to fetch rules');
        const rules = await response.json();
        currentAuditRules = rules;
        
        const tbody = els.auditRulesTbody;
        if (!tbody) return;
        
        if (rules.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted py-4">目前無任何盤查規則</td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = rules.map(rule => {
            let ipText = rule.ip || '';
            let showAlias = rule.ip_alias;
            if (ipText.toLowerCase() === 'internal') {
                ipText = 'Private IP';
                showAlias = '';
            } else if (ipText.toLowerCase() === 'external') {
                ipText = 'Public IP';
                showAlias = '';
            }
            const ipAliasSub = showAlias ? `<div class="domain-subtext" style="font-size: 0.75rem; color: var(--text-muted);">${showAlias}</div>` : '';
            const ipDisplay = rule.ip ? `<div>${ipText}</div>${ipAliasSub}` : '<span class="text-muted">(任意)</span>';
            const portAliasSub = rule.port_name ? `<div class="domain-subtext" style="font-size: 0.75rem; color: var(--text-muted);">${rule.port_name}</div>` : '';
            const portDisplay = rule.port ? `<div>${rule.port}</div>${portAliasSub}` : '<span class="text-muted">(任意)</span>';
            const badgeClass = rule.flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
            const flagText = rule.flag === 'watch' ? '關注' : '異常';
            
            let sourceBadge = '';
            if (rule.scenario_id) {
                sourceBadge = `<span class="badge" style="background: rgba(99, 102, 241, 0.18); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.35); font-size: 0.72rem; padding: 2px 7px; border-radius: 4px; display: inline-flex; align-items: center; gap: 3px;" title="由智慧情境「${escapeHtml(rule.scenario_name || '')}」自動同步">🏷️ 情境關聯: ${escapeHtml(rule.scenario_name || '')}</span>`;
            } else {
                sourceBadge = `<span class="badge" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); font-size: 0.72rem; padding: 2px 7px; border-radius: 4px; display: inline-flex; align-items: center; gap: 3px;">⚙️ 自訂手動</span>`;
            }

            return `
                <tr>
                    <td style="padding: 10px 12px; font-family: var(--font-mono);">${ipDisplay}</td>
                    <td style="padding: 10px 12px; font-family: var(--font-mono);">${portDisplay}</td>
                    <td style="padding: 10px 12px;">${sourceBadge}</td>
                    <td style="padding: 10px 12px; text-align: center;">
                        <span class="badge ${badgeClass}" style="cursor: pointer;" title="點擊編輯規則" onclick="openEditAuditRuleModal(${rule.id})">${flagText}</span>
                    </td>
                    <td style="padding: 10px 12px; text-align: right; white-space: nowrap;">
                        <button class="btn btn-secondary btn-sm" onclick="openEditAuditRuleModal(${rule.id})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; margin-right: 6px;">
                            編輯
                        </button>
                        <button class="btn btn-secondary btn-sm" onclick="deleteAuditRule(${rule.id})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">
                            刪除
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (err) {
        console.error('Error fetching audit rules:', err);
    }
}

// Open Edit Audit Rule Modal
function openEditAuditRuleModal(ruleId) {
    const rule = currentAuditRules.find(r => r.id === ruleId);
    if (!rule) return;
    
    if (els.editRuleId) els.editRuleId.value = rule.id;
    if (els.editRuleErrorMessage) {
        els.editRuleErrorMessage.style.display = 'none';
        els.editRuleErrorMessage.innerText = '';
    }
    
    const rawIp = rule.ip || '';
    if (els.editRuleSelectIpType && els.editRuleInputIp) {
        if (!rawIp) {
            els.editRuleSelectIpType.value = '';
            els.editRuleInputIp.style.display = 'none';
            els.editRuleInputIp.value = '';
        } else if (rawIp.toLowerCase() === 'internal') {
            els.editRuleSelectIpType.value = 'internal';
            els.editRuleInputIp.style.display = 'none';
            els.editRuleInputIp.value = '';
        } else if (rawIp.toLowerCase() === 'external') {
            els.editRuleSelectIpType.value = 'external';
            els.editRuleInputIp.style.display = 'none';
            els.editRuleInputIp.value = '';
        } else {
            els.editRuleSelectIpType.value = 'custom';
            els.editRuleInputIp.style.display = 'block';
            els.editRuleInputIp.value = rawIp;
        }
    }
    
    if (els.editRuleInputPort) {
        els.editRuleInputPort.value = rule.port || '';
    }
    
    const flagRadios = document.querySelectorAll('input[name="edit-rule-input-flag"]');
    flagRadios.forEach(radio => {
        radio.checked = (radio.value === rule.flag);
    });
    
    if (els.modalEditAuditRule) {
        els.modalEditAuditRule.classList.add('active');
    }
}

// Close Edit Audit Rule Modal
function closeEditRuleModal() {
    if (els.modalEditAuditRule) {
        els.modalEditAuditRule.classList.remove('active');
    }
    if (els.editRuleErrorMessage) {
        els.editRuleErrorMessage.style.display = 'none';
        els.editRuleErrorMessage.innerText = '';
    }
}

// Show error in Edit Modal
function showEditRuleError(msg) {
    if (els.editRuleErrorMessage) {
        els.editRuleErrorMessage.innerText = msg;
        els.editRuleErrorMessage.style.display = 'block';
    }
}

// Submit edited rule with duplicate check
async function submitEditAuditRule(e) {
    if (e) e.preventDefault();
    if (!els.editRuleId) return;
    const ruleId = parseInt(els.editRuleId.value, 10);
    if (!ruleId) return;
    
    let ip = '';
    if (els.editRuleSelectIpType) {
        const type = els.editRuleSelectIpType.value;
        if (type === 'custom') {
            ip = els.editRuleInputIp ? els.editRuleInputIp.value.trim() : '';
            if (!ip) {
                showEditRuleError('請輸入自訂 IP 或 CIDR！');
                return;
            }
        } else {
            ip = type;
        }
    }
    
    const port = els.editRuleInputPort ? els.editRuleInputPort.value.trim() : '';
    const flagEl = document.querySelector('input[name="edit-rule-input-flag"]:checked');
    const flag = flagEl ? flagEl.value : 'watch';
    
    if (!ip && !port) {
        showEditRuleError('IP 與 Port 不能同時為空！');
        return;
    }
    
    // Duplicate check against current rules (excluding self)
    const normalizedNewIp = ip ? ip.toLowerCase() : '';
    const normalizedNewPort = port || '';
    const isDuplicate = currentAuditRules.some(r => {
        if (r.id === ruleId) return false;
        const existingIp = (r.ip || '').toLowerCase();
        const existingPort = r.port || '';
        return existingIp === normalizedNewIp && existingPort === normalizedNewPort;
    });
    
    if (isDuplicate) {
        showEditRuleError('已存在相同 IP/CIDR 與 Port 的比對規則，無法重複儲存！');
        return;
    }
    
    try {
        const response = await fetch(`/api/audit/rules/${ruleId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip || null, port: port || null, flag })
        });
        
        const data = await response.json();
        if (response.ok) {
            closeEditRuleModal();
            showAuditRuleStatus('規則已成功更新！', 'success');
            fetchAuditRules();
        } else {
            showEditRuleError(data.detail || '更新失敗');
        }
    } catch (err) {
        showEditRuleError(`連線錯誤: ${err.message}`);
    }
}

// Submit new rule with duplicate check
async function submitAuditRule() {
    const ipSelect = document.getElementById('audit-select-ip-type');
    let ip = '';
    if (ipSelect) {
        const type = ipSelect.value;
        if (type === 'custom') {
            ip = els.auditInputIp.value.trim();
        } else {
            ip = type;
        }
    } else {
        ip = els.auditInputIp.value.trim();
    }
    const port = els.auditInputPort.value.trim();
    
    const flagEl = document.querySelector('input[name="audit-input-flag"]:checked');
    const flag = flagEl ? flagEl.value : 'watch';
    
    if (!ip && !port) {
        showAuditRuleStatus('IP 與 Port 不能同時為空！', 'error');
        return;
    }
    
    // Duplicate check against current rules
    const normalizedNewIp = ip ? ip.toLowerCase() : '';
    const normalizedNewPort = port || '';
    const isDuplicate = currentAuditRules.some(r => {
        const existingIp = (r.ip || '').toLowerCase();
        const existingPort = r.port || '';
        return existingIp === normalizedNewIp && existingPort === normalizedNewPort;
    });
    
    if (isDuplicate) {
        showAuditRuleStatus('已存在相同 IP/CIDR 與 Port 的比對規則，無法重複新增！', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/audit/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip || null, port: port || null, flag })
        });
        
        const data = await response.json();
        if (response.ok) {
            showAuditRuleStatus('規則儲存成功！', 'success');
            if (ipSelect) {
                ipSelect.value = '';
                els.auditInputIp.style.display = 'none';
            }
            els.auditInputIp.value = '';
            els.auditInputPort.value = '';
            fetchAuditRules();
        } else {
            showAuditRuleStatus(data.detail || '儲存失敗', 'error');
        }
    } catch (err) {
        showAuditRuleStatus(`連線錯誤: ${err.message}`, 'error');
    }
}

// Delete audit rule
async function deleteAuditRule(ruleId) {
    if (!confirm('確定要刪除此比對規則嗎？')) return;
    try {
        const response = await fetch(`/api/audit/rules/${ruleId}`, { method: 'DELETE' });
        if (response.ok) {
            fetchAuditRules();
        } else {
            const data = await response.json();
            alert(data.detail || '刪除失敗');
        }
    } catch (err) {
        alert(`連線錯誤: ${err.message}`);
    }
}

// Make functions globally available
window.openEditAuditRuleModal = openEditAuditRuleModal;
window.closeEditRuleModal = closeEditRuleModal;
window.submitEditAuditRule = submitEditAuditRule;
window.deleteAuditRule = deleteAuditRule;

// Fetch last audit status
async function fetchAuditStatus() {
    try {
        const response = await fetch('/api/audit/status');
        if (!response.ok) throw new Error('Failed to fetch audit status');
        const status = await response.json();
        
        els.auditLastRunTime.innerText = status.run_ts || '-';
        if (els.auditNextRunTime) {
            els.auditNextRunTime.innerText = status.next_run_ts || '-';
        }
        els.auditLastRunMatches.innerText = status.records_matched !== undefined ? `${status.records_matched} 筆` : '-';
        els.auditLastRunMessage.innerText = status.message || '-';
        
        const badge = els.auditLastRunStatus;
        if (badge) {
            badge.innerText = status.status === 'success' ? '成功' : (status.status === 'failed' ? '失敗' : '無');
            badge.className = 'badge';
            if (status.status === 'success') {
                badge.classList.add('badge-success');
            } else if (status.status === 'failed') {
                badge.classList.add('badge-danger');
            } else {
                badge.classList.add('badge-info');
            }
        }
    } catch (err) {
        console.error('Error fetching audit status:', err);
    }
}

// Helper to render Threat Intel inline badges on IP & Port cells
function renderFlowIntelBadge(intel) {
    if (!intel) return '';
    const score = intel.risk_score || 0;
    const lvl = (intel.risk_level || 'safe').toLowerCase();
    const prov = escapeHtml(intel.provider || 'ThreatIntel');
    const summary = escapeHtml(intel.summary || '');
    const riskyPorts = intel.risky_ports ? `｜風險埠: ${escapeHtml(intel.risky_ports)}` : '';
    let bg = 'rgba(16, 185, 129, 0.14)', col = '#34d399', bdr = 'rgba(16, 185, 129, 0.35)', icon = '🟢';
    if (lvl === 'critical' || lvl === 'high') {
        bg = 'rgba(239, 68, 68, 0.18)'; col = '#f87171'; bdr = 'rgba(239, 68, 68, 0.45)'; icon = '🔴';
    } else if (lvl === 'medium') {
        bg = 'rgba(245, 158, 11, 0.18)'; col = '#fbbf24'; bdr = 'rgba(245, 158, 11, 0.45)'; icon = '🟠';
    } else if (lvl === 'low') {
        bg = 'rgba(14, 165, 233, 0.16)'; col = '#38bdf8'; bdr = 'rgba(14, 165, 233, 0.35)'; icon = '🟡';
    }
    return `<div style="margin-top: 3px;"><span class="badge" style="background:${bg};color:${col};border:1px solid ${bdr};font-size:0.7rem;padding:1px 6px;border-radius:4px;display:inline-flex;align-items:center;gap:3px;" title="${summary}">${icon} 風險 ${score}${riskyPorts} (${prov})</span></div>`;
}

function renderFlowPortRiskTag(portNo, srcIntel, dstIntel) {
    if (portNo === null || portNo === undefined) return '';
    const pStr = String(portNo);
    const checkIntel = (intel) => {
        if (!intel || !intel.risky_ports) return false;
        return intel.risky_ports.split(',').map(s => s.trim()).includes(pStr);
    };
    if (checkIntel(srcIntel) || checkIntel(dstIntel)) {
        return `<div style="font-size:0.7rem;color:#f87171;font-weight:600;margin-top:2px;" title="此連接埠被威脅情資庫標記為具有高風險或已知弱點">⚠️ 風險 Port</div>`;
    }
    return '';
}

// Trigger manual audit
async function triggerManualAudit(startTime = null, timeRange = null) {
    if (!timeRange && !startTime) {
        const selectRange = document.getElementById('select-quick-audit-range');
        if (selectRange) timeRange = selectRange.value;
    }
    const btn = els.btnTriggerAudit;
    const labelEl = document.getElementById('label-trigger-audit');
    const bannerEl = document.getElementById('audit-checking-banner');
    const bannerTextEl = document.getElementById('audit-checking-banner-text');

    if (btn) {
        btn.classList.add('btn-refresh-loading');
        btn.disabled = true;
        btn.querySelectorAll('i, svg, .lucide').forEach(el => el.classList.add('icon-spinning', 'icon-spin'));
    }
    if (labelEl) labelEl.innerText = '盤查檢查中...';
    if (bannerEl) bannerEl.style.display = 'inline-flex';
    if (bannerTextEl) bannerTextEl.innerText = '正在執行流量比對與外部 IP 威脅情資檢查中，請稍候...';

    showAuditTriggerStatus('正在執行流量比對盤查與外部 IP 威脅情資比對，請稍候...', 'info');
    const minSpinDelay = new Promise(r => setTimeout(r, 700));
    
    try {
        const reqBody = {};
        if (startTime) reqBody.start_time = startTime;
        if (timeRange) reqBody.time_range = timeRange;
        
        const [response] = await Promise.all([
            fetch('/api/audit/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reqBody)
            }),
            minSpinDelay
        ]);
        const data = await response.json();
        
        if (response.ok) {
            const count = data.records_matched || 0;
            const ist = data.intel_stats || {};
            const cachedHits = ist.intel_cached_hits || 0;
            const newQueried = ist.intel_queried_new || 0;
            const riskyIps = ist.intel_risky_ips || 0;
            const prov = ist.intel_provider_used || 'DB 快取';
            const summaryMsg = `共比對匹配 ${count} 筆流量｜外部 IP 情資：快取命中 ${cachedHits} 筆、新詢問 API ${newQueried} 筆（發現 ${riskyIps} 個風險 IP，來源：${prov}）`;
            showAuditTriggerStatus(`盤查成功！${summaryMsg}`, 'success');
            showToast(summaryMsg, 'success', '盤查與情資比對完成');
            fetchAuditStatus();
            fetchAuditMatches();
            fetchAuditRules();
            fetchThreatIntelCache();
            fetchSmartDiagnostics();
        } else {
            showAuditTriggerStatus(data.detail || '盤查執行失敗', 'error');
            showToast(data.detail || '盤查執行失敗', 'error', '盤查失敗');
        }
    } catch (err) {
        showAuditTriggerStatus(`連線錯誤: ${err.message}`, 'error');
        showToast(`連線錯誤: ${err.message}`, 'error', '連線錯誤');
    } finally {
        if (btn) {
            btn.classList.remove('btn-refresh-loading');
            btn.disabled = false;
            btn.querySelectorAll('i, svg, .lucide').forEach(el => el.classList.remove('icon-spinning', 'icon-spin'));
        }
        if (labelEl) labelEl.innerText = '立即盤查';
        if (bannerEl) bannerEl.style.display = 'none';
        if (window.lucide) window.lucide.createIcons();
    }
}

// Fetch permanently matched records
// Fetch permanently matched records (Anomalous Traffic Report)
async function fetchAuditMatches() {
    const limit = state.auditPagination.limit;
    const offset = state.auditPagination.offset;
    
    let url = `/api/audit/matches?limit=${limit}&offset=${offset}&sort_by=${state.auditSorting.by}&sort_order=${state.auditSorting.order}`;
    if (state.auditFilters.src) url += `&src=${encodeURIComponent(state.auditFilters.src)}`;
    if (state.auditFilters.dst) url += `&dst=${encodeURIComponent(state.auditFilters.dst)}`;
    if (state.auditFilters.port) url += `&port=${encodeURIComponent(state.auditFilters.port)}`;
    if (state.auditFilters.flag) url += `&flag=${encodeURIComponent(state.auditFilters.flag)}`;
    
    try {
        const signal = getAbortSignal('auditMatches');
        const response = await fetch(url, { signal });
        if (!response.ok) throw new Error('Failed to fetch matched records');
        const data = await response.json();
        
        state.auditRecords = data.records; // Cache rules records in state
        state.auditPagination.total = data.total;
        if (els.auditTotalFiltered) els.auditTotalFiltered.innerText = data.total;
        
        renderAuditMatches(data.records);
        renderAuditPagination(data.total);
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Error fetching audit matches:', err);
        const tbody = els.auditMatchesTbody;
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="13" class="text-center text-danger py-4">載入失敗: ${err.message}</td></tr>`;
        }
    }
}

// Render matches table
function renderAuditMatches(records) {
    const tbody = els.auditMatchesTbody;
    if (!tbody) return;
    
    if (records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="11" class="text-center text-muted py-5">無任何比對符合的流量存檔資料</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = records.map((r, idx) => {
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注' : '異常';
        
        const exporterSub = r.exporter_alias ? `<div class="domain-subtext" title="${r.exporter_alias}">${r.exporter_alias}</div>` : '';
        const srcDomainSub = r.src_domain ? `<div class="domain-subtext">${escapeHtml(r.src_domain)}</div>` : '';
        const dstDomainSub = r.dst_domain ? `<div class="domain-subtext">${escapeHtml(r.dst_domain)}</div>` : '';
        const srcIntelBadge = renderFlowIntelBadge(r.src_intel);
        const dstIntelBadge = renderFlowIntelBadge(r.dst_intel);
        const sportAliasSub = r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : '';
        const dportAliasSub = r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : '';
        const sportRiskSub = renderFlowPortRiskTag(r.sport, r.src_intel, r.dst_intel);
        const dportRiskSub = renderFlowPortRiskTag(r.dport, r.src_intel, r.dst_intel);
        
        return `
            <tr class="flow-row" onclick="showAuditFlowDetails(${idx})">
                <td style="padding: 10px 12px; font-family: var(--font-mono);">${r.ts}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <span class="badge ${badgeClass}">${flagText}</span>
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.exporter || 'N/A'}</div>
                    ${exporterSub}
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.src}</div>
                    ${srcDomainSub}
                    ${srcIntelBadge}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.sport}</div>
                    ${sportAliasSub}
                    ${sportRiskSub}
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.dst}</div>
                    ${dstDomainSub}
                    ${dstIntelBadge}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.dport}</div>
                    ${dportAliasSub}
                    ${dportRiskSub}
                </td>
                <td style="padding: 10px 12px;"><span class="badge badge-info">${r.proto_name}</span></td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono);">${r.packets.toLocaleString()}</td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono); font-weight: 500;">${formatBytes(r.octets)}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <button class="btn-delete-match" data-id="${r.id}" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 2px 6px; border-radius: 4px; transition: background 0.2s;">
                        <i data-lucide="trash-2" style="width: 14px; height: 14px;"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
    
    // Bind delete actions
    tbody.querySelectorAll('.btn-delete-match').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const matchId = btn.getAttribute('data-id');
            if (!confirm('確認要刪除此筆異常流量報告？')) return;
            try {
                const res = await fetch(`/api/audit/matches/${encodeURIComponent(matchId)}`, { method: 'DELETE' });
                if (!res.ok) throw new Error('Delete request failed');
                fetchAuditMatches();
            } catch (err) {
                alert(`刪除失敗: ${err.message}`);
            }
        });
    });
    
    // Re-render Lucide icons
    lucide.createIcons();
}

// Render pagination buttons for audit
function renderAuditPagination(total) {
    const el = els.auditPagination;
    if (!el) return;
    
    const limit = state.auditPagination.limit;
    const currentOffset = state.auditPagination.offset;
    const totalPages = Math.ceil(total / limit);
    const currentPage = Math.floor(currentOffset / limit) + 1;
    
    if (totalPages <= 1) {
        el.innerHTML = '';
        return;
    }
    
    let html = '';
    
    // Prev button
    const prevDisabled = currentPage === 1 ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${prevDisabled} onclick="changeAuditPage(${currentPage - 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&laquo;</button>`;
    
    // Page indicators
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? 'active' : '';
        const style = i === currentPage ? 'background: var(--color-primary); border-color: var(--color-primary); color: white;' : '';
        html += `<button class="btn btn-secondary btn-sm ${activeClass}" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; ${style}" onclick="changeAuditPage(${i})">${i}</button>`;
    }
    
    // Next button
    const nextDisabled = currentPage === totalPages ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${nextDisabled} onclick="changeAuditPage(${currentPage + 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&raquo;</button>`;
    
    el.innerHTML = html;
}

// Change audit matches page helper
function changeAuditPage(pageNum) {
    const limit = state.auditPagination.limit;
    state.auditPagination.offset = (pageNum - 1) * limit;
    fetchAuditMatches();
}

// Clear matched flows
async function clearAuditMatches() {
    if (!confirm('⚠️ 警告：確定要永久清除所有異常流量報告嗎？此操作將會清空該表，且無法復原！')) return;
    
    try {
        const response = await fetch('/api/audit/matches', { method: 'DELETE' });
        const data = await response.json();
        
        if (response.ok) {
            alert(data.message || '清除成功。');
            state.auditPagination.offset = 0;
            fetchAuditMatches();
        } else {
            alert(data.detail || '清除失敗');
        }
    } catch (err) {
        alert(`連線錯誤: ${err.message}`);
    }
}

// Show details modal specifically for audit records
function showAuditFlowDetails(idx) {
    const r = state.auditRecords[idx];
    if (!r) return;
    
    // Display Matched Rule Section
    if (els.detailRuleSection) {
        els.detailRuleSection.style.display = 'block';
        
        let ruleIpDisplay = '(任意)';
        if (r.rule_ip) {
            const lowerIp = r.rule_ip.toLowerCase();
            ruleIpDisplay = lowerIp === 'internal' ? 'Private IP' : (lowerIp === 'external' ? 'Public IP' : r.rule_ip);
            if (r.rule_ip_alias && lowerIp !== 'internal' && lowerIp !== 'external') {
                ruleIpDisplay += ` (${r.rule_ip_alias})`;
            }
        }
        els.detailRuleIp.innerText = ruleIpDisplay;
        els.detailRulePort.innerText = r.rule_port || '(任意)';
        
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注 (Watch)' : '異常 (Anomaly)';
        els.detailMatchFlag.className = `badge ${badgeClass}`;
        els.detailMatchFlag.innerText = flagText;
        
        els.detailMatchTs.innerText = r.match_ts ? formatSqlTimestamp(r.match_ts) : 'N/A';
    }
    
    els.detailId.innerText = r.id || 'N/A';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'N/A';
    els.detailType.innerText = r.proto ? r.proto.toUpperCase() : 'N/A';
    els.detailType.className = `value badge ${r.proto === 'ipfix' ? 'badge-info' : (r.proto === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    const exporterAlias = r.exporter_alias ? ` (${r.exporter_alias})` : '';
    els.detailExporter.innerText = `${r.exporter || 'N/A'}${exporterAlias}`;
    els.detailSrc.innerText = r.src || 'N/A';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'N/A';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || r.proto || 'N/A';
    els.detailOctets.innerText = `${formatNumber(r.octets)} 位元組 (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Parse json_data
    let raw = {};
    if (r.json_data) {
        try {
            raw = JSON.parse(r.json_data);
        } catch (e) {
            raw = { error: "解析 json_data 失敗", raw: r.json_data };
        }
    }
    els.detailRawJson.innerText = JSON.stringify(raw, null, 2);
    els.detailsModal.classList.add('active');
}

// Fetch Anomalous Report records for new tab (with filters)
async function fetchAnomalousReport() {
    const limit = state.anomaliesPagination.limit;
    const offset = state.anomaliesPagination.offset;
    
    let url = `/api/audit/matches?limit=${limit}&offset=${offset}&sort_by=${state.auditSorting.by}&sort_order=${state.auditSorting.order}`;
    if (state.anomaliesFilters.ip) url += `&ip=${encodeURIComponent(state.anomaliesFilters.ip)}`;
    if (state.anomaliesFilters.src) url += `&src=${encodeURIComponent(state.anomaliesFilters.src)}`;
    if (state.anomaliesFilters.dst) url += `&dst=${encodeURIComponent(state.anomaliesFilters.dst)}`;
    if (state.anomaliesFilters.port) url += `&port=${encodeURIComponent(state.anomaliesFilters.port)}`;
    if (state.anomaliesFilters.sport) url += `&sport=${encodeURIComponent(state.anomaliesFilters.sport)}`;
    if (state.anomaliesFilters.dport) url += `&dport=${encodeURIComponent(state.anomaliesFilters.dport)}`;
    if (state.anomaliesFilters.proto) url += `&proto=${encodeURIComponent(state.anomaliesFilters.proto)}`;
    if (state.anomaliesFilters.flag) url += `&flag=${encodeURIComponent(state.anomaliesFilters.flag)}`;
    
    // Dynamic multi-conditions
    if (state.anomaliesFilters.conditions && state.anomaliesFilters.conditions.length > 0) {
        const validConds = state.anomaliesFilters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            url += `&conditions=${encodeURIComponent(JSON.stringify(validConds))}&logic=${encodeURIComponent(state.anomaliesFilters.logic || 'AND')}`;
        }
    }
    
    try {
        const signal = getAbortSignal('anomaliesReport');
        const response = await fetch(url, { signal });
        if (!response.ok) throw new Error('Failed to fetch anomalous records');
        const data = await response.json();
        
        state.anomaliesRecords = data.records; // Cache in state
        state.anomaliesPagination.total = data.total;
        els.anomaliesTotalFiltered.innerText = data.total;
        
        renderAnomalousReportTable(data.records);
        renderAnomaliesPagination(data.total);
        fetchAnomalousReportStats();
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Error fetching anomalous reports:', err);
        const tbody = els.anomaliesTbody;
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="12" class="text-center text-danger py-4">載入失敗: ${err.message}</td></tr>`;
        }
    }
}

// Render Anomalous Report table
function renderAnomalousReportTable(records) {
    const tbody = els.anomaliesTbody;
    if (!tbody) return;
    
    if (records.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="10" class="text-center text-muted py-5">無任何異常流量報告資料</td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = records.map((r, idx) => {
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注' : '異常';
        
        const exporterSub = r.exporter_alias ? `<div class="domain-subtext" title="${r.exporter_alias}">${r.exporter_alias}</div>` : '';
        const srcDomainSub = r.src_domain ? `<div class="domain-subtext">${escapeHtml(r.src_domain)}</div>` : '';
        const dstDomainSub = r.dst_domain ? `<div class="domain-subtext">${escapeHtml(r.dst_domain)}</div>` : '';
        const srcIntelBadge = renderFlowIntelBadge(r.src_intel);
        const dstIntelBadge = renderFlowIntelBadge(r.dst_intel);
        const sportAliasSub = r.sport_name ? `<div class="domain-subtext" title="${r.sport_name}">${r.sport_name}</div>` : '';
        const dportAliasSub = r.dport_name ? `<div class="domain-subtext" title="${r.dport_name}">${r.dport_name}</div>` : '';
        const sportRiskSub = renderFlowPortRiskTag(r.sport, r.src_intel, r.dst_intel);
        const dportRiskSub = renderFlowPortRiskTag(r.dport, r.src_intel, r.dst_intel);
        
        return `
            <tr class="flow-row" onclick="showAnomaliesFlowDetails(${idx})">
                <td style="padding: 10px 12px; font-family: var(--font-mono);">${r.ts}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <span class="badge ${badgeClass}">${flagText}</span>
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.exporter || 'N/A'}</div>
                    ${exporterSub}
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.src}</div>
                    ${srcDomainSub}
                    ${srcIntelBadge}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.sport}</div>
                    ${sportAliasSub}
                    ${sportRiskSub}
                </td>
                <td style="padding: 10px 12px;">
                    <div style="font-family: var(--font-mono);">${r.dst}</div>
                    ${dstDomainSub}
                    ${dstIntelBadge}
                </td>
                <td style="padding: 10px 12px; font-family: var(--font-mono);">
                    <div>${r.dport}</div>
                    ${dportAliasSub}
                    ${dportRiskSub}
                </td>
                <td style="padding: 10px 12px;"><span class="badge badge-info">${r.proto_name}</span></td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono);">${r.packets.toLocaleString()}</td>
                <td style="padding: 10px 12px; text-align: right; font-family: var(--font-mono); font-weight: 500;">${formatBytes(r.octets)}</td>
            </tr>
        `;
    }).join('');
    
    lucide.createIcons();
}

// Pagination logic for anomalies report
function renderAnomaliesPagination(total) {
    const el = els.anomaliesPagination;
    if (!el) return;
    
    const limit = state.anomaliesPagination.limit;
    const currentOffset = state.anomaliesPagination.offset;
    const totalPages = Math.ceil(total / limit);
    const currentPage = Math.floor(currentOffset / limit) + 1;
    
    if (totalPages <= 1) {
        el.innerHTML = '';
        return;
    }
    
    let html = '';
    const prevDisabled = currentPage === 1 ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${prevDisabled} onclick="changeAnomaliesPage(${currentPage - 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&laquo;</button>`;
    
    const startPage = Math.max(1, currentPage - 2);
    const endPage = Math.min(totalPages, currentPage + 2);
    
    for (let i = startPage; i <= endPage; i++) {
        const activeClass = i === currentPage ? 'active' : '';
        const style = i === currentPage ? 'background: var(--color-primary); border-color: var(--color-primary); color: white;' : '';
        html += `<button class="btn btn-secondary btn-sm ${activeClass}" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px; ${style}" onclick="changeAnomaliesPage(${i})">${i}</button>`;
    }
    
    const nextDisabled = currentPage === totalPages ? 'disabled' : '';
    html += `<button class="btn btn-secondary btn-sm" ${nextDisabled} onclick="changeAnomaliesPage(${currentPage + 1})" style="padding: 4px 8px; font-size: 0.75rem; border-radius: 4px;">&raquo;</button>`;
    
    el.innerHTML = html;
}

function changeAnomaliesPage(page) {
    const limit = state.anomaliesPagination.limit;
    state.anomaliesPagination.offset = (page - 1) * limit;
    fetchAnomalousReport();
}

// Show details modal specifically for anomalies records
function showAnomaliesFlowDetails(idx) {
    const r = state.anomaliesRecords[idx];
    if (!r) return;
    
    // Display Matched Rule Section
    if (els.detailRuleSection) {
        els.detailRuleSection.style.display = 'block';
        
        let ruleIpDisplay = '(任意)';
        if (r.rule_ip) {
            const lowerIp = r.rule_ip.toLowerCase();
            ruleIpDisplay = lowerIp === 'internal' ? 'Private IP' : (lowerIp === 'external' ? 'Public IP' : r.rule_ip);
            if (r.rule_ip_alias && lowerIp !== 'internal' && lowerIp !== 'external') {
                ruleIpDisplay += ` (${r.rule_ip_alias})`;
            }
        }
        els.detailRuleIp.innerText = ruleIpDisplay;
        els.detailRulePort.innerText = r.rule_port || '(任意)';
        
        const badgeClass = r.match_flag === 'watch' ? 'badge-watch' : 'badge-anomaly';
        const flagText = r.match_flag === 'watch' ? '關注 (Watch)' : '異常 (Anomaly)';
        els.detailMatchFlag.className = `badge ${badgeClass}`;
        els.detailMatchFlag.innerText = flagText;
        
        els.detailMatchTs.innerText = r.match_ts ? formatSqlTimestamp(r.match_ts) : 'N/A';
    }
    
    els.detailId.innerText = r.id || 'N/A';
    els.detailTs.innerText = r.ts ? formatSqlTimestamp(r.ts) : 'N/A';
    els.detailType.innerText = r.proto ? r.proto.toUpperCase() : 'N/A';
    els.detailType.className = `value badge ${r.proto === 'ipfix' ? 'badge-info' : (r.proto === 'netflow9' ? 'badge-primary' : 'badge-warning')}`;
    const exporterAlias = r.exporter_alias ? ` (${r.exporter_alias})` : '';
    els.detailExporter.innerText = `${r.exporter || 'N/A'}${exporterAlias}`;
    els.detailSrc.innerText = r.src || 'N/A';
    els.detailSrcDomain.innerText = r.src_domain || 'N/A';
    els.detailDst.innerText = r.dst || 'N/A';
    els.detailDstDomain.innerText = r.dst_domain || 'N/A';
    els.detailProto.innerText = r.proto_name || r.proto || 'N/A';
    els.detailOctets.innerText = `${formatNumber(r.octets)} 位元組 (${formatBytes(r.octets)})`;
    els.detailPackets.innerText = formatNumber(r.packets);
    
    // Parse json_data
    let raw = {};
    if (r.json_data) {
        try {
            raw = JSON.parse(r.json_data);
        } catch (e) {
            raw = { error: "解析 json_data 失敗", raw: r.json_data };
        }
    }
    els.detailRawJson.innerText = JSON.stringify(raw, null, 2);
    els.detailsModal.classList.add('active');
}

// Show rule status helper
function showAuditRuleStatus(message, type) {
    const el = els.auditRuleStatusMessage;
    if (!el) return;
    
    el.style.display = 'block';
    el.innerText = message;
    el.style.backgroundColor = '';
    el.style.color = '';
    el.style.border = '';
    
    if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    }
    
    setTimeout(() => {
        el.style.display = 'none';
    }, 4000);
}

// Show manual trigger status helper
function showAuditTriggerStatus(message, type) {
    const el = els.auditTriggerStatus;
    if (!el) return;
    
    el.style.display = 'block';
    el.innerText = message;
    el.style.backgroundColor = '';
    el.style.color = '';
    el.style.border = '';
    
    if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else { // info
        el.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
        el.style.color = '#818cf8';
        el.style.border = '1px solid rgba(99, 102, 241, 0.3)';
    }
    
    setTimeout(() => {
        el.style.display = 'none';
    }, 5000);
}

// Fetch statistics for anomalous report view and render the two bar charts
async function fetchAnomalousReportStats() {
    let url = `/api/audit/matches/stats?`;
    if (state.anomaliesFilters.ip) url += `&ip=${encodeURIComponent(state.anomaliesFilters.ip)}`;
    if (state.anomaliesFilters.src) url += `&src=${encodeURIComponent(state.anomaliesFilters.src)}`;
    if (state.anomaliesFilters.dst) url += `&dst=${encodeURIComponent(state.anomaliesFilters.dst)}`;
    if (state.anomaliesFilters.port) url += `&port=${encodeURIComponent(state.anomaliesFilters.port)}`;
    if (state.anomaliesFilters.sport) url += `&sport=${encodeURIComponent(state.anomaliesFilters.sport)}`;
    if (state.anomaliesFilters.dport) url += `&dport=${encodeURIComponent(state.anomaliesFilters.dport)}`;
    if (state.anomaliesFilters.proto) url += `&proto=${encodeURIComponent(state.anomaliesFilters.proto)}`;
    if (state.anomaliesFilters.flag) url += `&flag=${encodeURIComponent(state.anomaliesFilters.flag)}`;

    // Dynamic multi-conditions
    if (state.anomaliesFilters.conditions && state.anomaliesFilters.conditions.length > 0) {
        const validConds = state.anomaliesFilters.conditions.map(c => {
            let finalVal = c.val;
            if (['src_ip', 'dst_ip', 'any_ip'].includes(c.field)) {
                if (c.ipType && c.ipType !== 'custom') {
                    finalVal = c.ipType;
                }
            }
            return { field: c.field, val: finalVal };
        }).filter(c => c.val && String(c.val).trim() !== '');

        if (validConds.length > 0) {
            url += `&conditions=${encodeURIComponent(JSON.stringify(validConds))}&logic=${encodeURIComponent(state.anomaliesFilters.logic || 'AND')}`;
        }
    }

    try {
        const signal = getAbortSignal('anomaliesStats');
        const response = await fetch(url, { signal });
        if (!response.ok) throw new Error('Failed to fetch stats');
        const data = await response.json();

        state.lastDrillStats = data;
        renderActiveDrillChart();
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Error fetching anomalous report stats:', err);
        const container = document.getElementById('drill-sankey-container');
        if (container) {
            container.innerHTML = `<div class="text-center text-danger py-4">載入統計圖表失敗: ${escapeHtml(err.message)}</div>`;
        }
    }
}

function renderActiveDrillChart() {
    const data = state.lastDrillStats;
    const selectEl = document.getElementById('drill-chart-mode-select');
    const hintEl = document.getElementById('drill-chart-hint');
    const summaryBadge = document.getElementById('drill-sankey-summary');
    const tooltip = document.getElementById('drill-sankey-tooltip');
    if (tooltip) tooltip.style.display = 'none';
    if (!data) return;

    const mode = selectEl ? selectEl.value : 'sankey';
    const totalBytes = data.total_bytes || 0;
    const totalFlows = data.total_flows || 0;

    if (mode === 'sankey') {
        if (hintEl) hintEl.innerText = '線寬代表傳輸量 (Bytes)，點擊節點可加入篩選';
        renderDrillSankeyDiagram(data.sankey_flows || [], totalBytes, totalFlows);
        return;
    }

    if (hintEl) hintEl.innerText = '滑鼠懸停顯示完整細項，點擊長條可即時加入篩選';

    if (mode === 'top_sources') {
        const items = (data.top_sources || []).map(x => ({
            key: String(x.src || ''),
            detail: x.domain || '',
            bytes: Number(x.bytes || 0),
            flows: Number(x.flows || 0),
            packets: Number(x.packets || 0)
        }));
        if (summaryBadge) summaryBadge.innerText = `Top ${items.length} 來源 IP · 總計 ${formatBytes(totalBytes)} (${formatNumber(totalFlows)} 筆)`;
        renderDrillTop10HorizontalBars(items, {
            title: 'Top 10 最高來源 IP',
            categoryLabel: '來源 IP',
            detailLabel: 'Domain / 別名',
            filterField: 'src_ip',
            barGradient: 'linear-gradient(90deg, #6366f1, #38bdf8)',
            accentColor: '#818cf8',
            totalBytes
        });
    } else if (mode === 'top_destinations') {
        const items = (data.top_destinations || []).map(x => ({
            key: String(x.dst || ''),
            detail: x.domain || '',
            bytes: Number(x.bytes || 0),
            flows: Number(x.flows || 0),
            packets: Number(x.packets || 0)
        }));
        if (summaryBadge) summaryBadge.innerText = `Top ${items.length} 目的 IP · 總計 ${formatBytes(totalBytes)} (${formatNumber(totalFlows)} 筆)`;
        renderDrillTop10HorizontalBars(items, {
            title: 'Top 10 最高目的 IP',
            categoryLabel: '目的 IP',
            detailLabel: 'Domain / 別名',
            filterField: 'dst_ip',
            barGradient: 'linear-gradient(90deg, #10b981, #34d399)',
            accentColor: '#34d399',
            totalBytes
        });
    } else if (mode === 'top_ports') {
        const items = (data.top_ports || []).map(x => ({
            key: String(x.port !== undefined && x.port !== null ? x.port : ''),
            detail: x.port_name || '',
            bytes: Number(x.bytes || 0),
            flows: Number(x.flows || 0),
            packets: 0
        }));
        if (summaryBadge) summaryBadge.innerText = `Top ${items.length} 連接埠 · 總計 ${formatBytes(totalBytes)} (${formatNumber(totalFlows)} 筆)`;
        renderDrillTop10HorizontalBars(items, {
            title: 'Top 10 最高 Port',
            categoryLabel: 'Port 號',
            detailLabel: '服務名稱',
            filterField: 'any_port',
            barGradient: 'linear-gradient(90deg, #f59e0b, #fbbf24)',
            accentColor: '#fbbf24',
            totalBytes
        });
    } else if (mode === 'top_overview') {
        if (summaryBadge) summaryBadge.innerText = `Top 10 三維度總覽 · 總計 ${formatBytes(totalBytes)} (${formatNumber(totalFlows)} 筆)`;
        renderDrillTop10Overview(data, totalBytes);
    }
}

function _buildHorizontalBarListHtml(items, opts, compact = false) {
    if (!items || items.length === 0) {
        return `<div class="text-center text-muted" style="padding: ${compact ? '48px' : '70px'} 0; font-size: 0.82rem;">目前篩選條件下無統計資料</div>`;
    }
    const maxBytes = Math.max(1, ...items.map(i => i.bytes));
    const denomBytes = Math.max(1, opts.totalBytes || items.reduce((s, i) => s + i.bytes, 0));
    const labelWidth = compact ? '122px' : '150px';
    const valWidth = compact ? '68px' : '88px';
    const barHeight = compact ? '18px' : '22px';

    return `
        <div style="display: flex; flex-direction: column; gap: ${compact ? '7px' : '9px'};">
            ${items.slice(0, 10).map((item, idx) => {
                const widthPct = Math.max(2, (item.bytes / maxBytes) * 100).toFixed(1);
                const sharePct = ((item.bytes / denomBytes) * 100).toFixed(1);
                const tipHtml = encodeURIComponent(`
                    <div style="font-weight:700;color:${opts.accentColor};margin-bottom:4px;">#${idx + 1} ${escapeHtml(opts.categoryLabel)}</div>
                    <div style="font-family:var(--font-mono);font-size:0.86rem;color:#f8fafc;">${escapeHtml(item.key)}</div>
                    ${item.detail ? `<div style="margin-top:3px;color:#cbd5e1;">${escapeHtml(opts.detailLabel)}：<strong>${escapeHtml(item.detail)}</strong></div>` : `<div style="margin-top:3px;color:#64748b;">${escapeHtml(opts.detailLabel)}：(無)</div>`}
                    <div style="margin-top:4px;color:#34d399;">流量：<strong>${formatBytes(item.bytes)}</strong> (${sharePct}%) · 連線：<strong>${formatNumber(item.flows)} 筆</strong></div>
                    ${item.packets > 0 ? `<div style="color:#94a3b8;font-size:0.74rem;">封包數：${formatNumber(item.packets)}</div>` : ''}
                    <div style="margin-top:4px;font-size:0.72rem;color:#94a3b8;">點擊此長條可即時加入篩選條件</div>
                `);
                return `
                    <div class="drill-hbar-row" data-field="${opts.filterField}" data-val="${escapeHtml(item.key)}" data-tip="${tipHtml}" style="display: flex; align-items: center; gap: 10px; cursor: pointer; padding: 2px 4px; border-radius: 6px; transition: background 0.15s;">
                        <div style="width: ${labelWidth}; flex-shrink: 0; text-align: right; font-family: var(--font-mono); font-size: ${compact ? '0.76rem' : '0.82rem'}; font-weight: 600; color: #f1f5f9; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                            ${escapeHtml(item.key)}
                        </div>
                        <div style="flex: 1; height: ${barHeight}; background: rgba(255, 255, 255, 0.06); border-radius: 5px; overflow: hidden; position: relative;">
                            <div style="width: ${widthPct}%; height: 100%; background: ${opts.barGradient}; border-radius: 5px; transition: width 0.35s ease; box-shadow: inset 0 1px 0 rgba(255,255,255,0.2);"></div>
                        </div>
                        <div style="width: ${valWidth}; flex-shrink: 0; text-align: right; font-family: var(--font-mono); font-size: ${compact ? '0.74rem' : '0.8rem'}; color: #cbd5e1; white-space: nowrap;">
                            ${formatBytes(item.bytes)}
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

function _bindHorizontalBarEvents(container) {
    const tooltip = document.getElementById('drill-sankey-tooltip');
    const showTip = (e, encodedHtml) => {
        if (!tooltip) return;
        tooltip.innerHTML = decodeURIComponent(encodedHtml);
        tooltip.style.display = 'block';
        const left = Math.min(window.innerWidth - 380, e.clientX + 14);
        const top = Math.min(window.innerHeight - 140, e.clientY + 14);
        tooltip.style.left = `${Math.max(10, left)}px`;
        tooltip.style.top = `${Math.max(10, top)}px`;
    };
    const hideTip = () => {
        if (tooltip) tooltip.style.display = 'none';
    };

    container.querySelectorAll('.drill-hbar-row').forEach(row => {
        row.addEventListener('mouseenter', (e) => {
            row.style.background = 'rgba(129, 140, 248, 0.14)';
            showTip(e, row.getAttribute('data-tip'));
        });
        row.addEventListener('mousemove', (e) => showTip(e, row.getAttribute('data-tip')));
        row.addEventListener('mouseleave', () => {
            row.style.background = 'transparent';
            hideTip();
        });
        row.addEventListener('click', () => {
            hideTip();
            applySankeyNodeFilter(row.getAttribute('data-field'), row.getAttribute('data-val'));
        });
    });
}

function renderDrillTop10HorizontalBars(items, opts) {
    const container = document.getElementById('drill-sankey-container');
    if (!container) return;
    container.innerHTML = `
        <div style="padding: 4px 6px;">
            ${_buildHorizontalBarListHtml(items, opts, false)}
        </div>
    `;
    _bindHorizontalBarEvents(container);
}

function renderDrillTop10Overview(data, totalBytes) {
    const container = document.getElementById('drill-sankey-container');
    if (!container) return;

    const srcItems = (data.top_sources || []).map(x => ({
        key: String(x.src || ''),
        detail: x.domain || '',
        bytes: Number(x.bytes || 0),
        flows: Number(x.flows || 0),
        packets: Number(x.packets || 0)
    }));
    const dstItems = (data.top_destinations || []).map(x => ({
        key: String(x.dst || ''),
        detail: x.domain || '',
        bytes: Number(x.bytes || 0),
        flows: Number(x.flows || 0),
        packets: Number(x.packets || 0)
    }));
    const portItems = (data.top_ports || []).map(x => ({
        key: String(x.port !== undefined && x.port !== null ? x.port : ''),
        detail: x.port_name || '',
        bytes: Number(x.bytes || 0),
        flows: Number(x.flows || 0),
        packets: 0
    }));

    container.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(3, minmax(260px, 1fr)); gap: 14px;">
            <div style="background: rgba(0, 0, 0, 0.22); border: 1px solid rgba(99, 102, 241, 0.28); border-radius: 10px; padding: 12px;">
                <div style="font-size: 0.84rem; font-weight: 700; color: #818cf8; margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between;">
                    <span>Top 10 來源 IP</span>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-weight: 400;">依傳輸量</span>
                </div>
                ${_buildHorizontalBarListHtml(srcItems, {
                    categoryLabel: '來源 IP',
                    detailLabel: 'Domain / 別名',
                    filterField: 'src_ip',
                    barGradient: 'linear-gradient(90deg, #6366f1, #38bdf8)',
                    accentColor: '#818cf8',
                    totalBytes
                }, true)}
            </div>
            <div style="background: rgba(0, 0, 0, 0.22); border: 1px solid rgba(16, 185, 129, 0.28); border-radius: 10px; padding: 12px;">
                <div style="font-size: 0.84rem; font-weight: 700; color: #34d399; margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between;">
                    <span>Top 10 目的 IP</span>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-weight: 400;">依傳輸量</span>
                </div>
                ${_buildHorizontalBarListHtml(dstItems, {
                    categoryLabel: '目的 IP',
                    detailLabel: 'Domain / 別名',
                    filterField: 'dst_ip',
                    barGradient: 'linear-gradient(90deg, #10b981, #34d399)',
                    accentColor: '#34d399',
                    totalBytes
                }, true)}
            </div>
            <div style="background: rgba(0, 0, 0, 0.22); border: 1px solid rgba(245, 158, 11, 0.28); border-radius: 10px; padding: 12px;">
                <div style="font-size: 0.84rem; font-weight: 700; color: #fbbf24; margin-bottom: 10px; display: flex; align-items: center; justify-content: space-between;">
                    <span>Top 10 Port</span>
                    <span style="font-size: 0.72rem; color: var(--text-muted); font-weight: 400;">依傳輸量</span>
                </div>
                ${_buildHorizontalBarListHtml(portItems, {
                    categoryLabel: 'Port 號',
                    detailLabel: '服務名稱',
                    filterField: 'any_port',
                    barGradient: 'linear-gradient(90deg, #f59e0b, #fbbf24)',
                    accentColor: '#fbbf24',
                    totalBytes
                }, true)}
            </div>
        </div>
    `;
    _bindHorizontalBarEvents(container);
}

function applySankeyNodeFilter(field, val) {
    if (!field || val === undefined || val === null || val === '') return;
    const strVal = String(val);
    const exists = (state.anomaliesFilters.conditions || []).some(c => c.field === field && String(c.val) === strVal);
    if (!exists) {
        state.anomaliesFilters.conditions.push({
            id: genConditionId(),
            field: field,
            ipType: 'custom',
            val: strVal
        });
        renderConditions('anomalies');
        state.anomaliesPagination.offset = 0;
        fetchAnomalousReport();
        showToast(`已加入篩選條件：${field} = ${strVal}`, 'info', '桑基圖互動篩選');
    }
}

function renderDrillSankeyDiagram(flows, totalBytes, totalFlows) {
    const container = document.getElementById('drill-sankey-container');
    const summaryBadge = document.getElementById('drill-sankey-summary');
    const tooltip = document.getElementById('drill-sankey-tooltip');
    if (!container) return;

    if (!flows || flows.length === 0) {
        if (summaryBadge) summaryBadge.innerText = '無流向資料';
        container.innerHTML = `<div class="text-center text-muted py-5" style="padding: 70px 0;">目前篩選條件下尚無可繪製的流量流向資料</div>`;
        return;
    }

    // Limit to top 18 flows for visual clarity
    const topFlows = flows.slice(0, 18);
    const shownBytes = topFlows.reduce((acc, f) => acc + (f.bytes || 0), 0);
    if (summaryBadge) {
        summaryBadge.innerText = `Top ${topFlows.length} 條主要流向 · 總計 ${formatBytes(totalBytes || shownBytes)} (${formatNumber(totalFlows || 0)} 筆)`;
    }

    // Aggregate nodes per column: Col 0 (src), Col 1 (dport), Col 2 (dst)
    const srcMap = new Map();
    const portMap = new Map();
    const dstMap = new Map();

    topFlows.forEach(f => {
        const b = Math.max(1, Number(f.bytes) || 0);
        const fl = Number(f.flows) || 0;
        const srcKey = f.src || 'Unknown';
        const portKey = String(f.dport !== undefined && f.dport !== null ? f.dport : 0);
        const dstKey = f.dst || 'Unknown';

        if (!srcMap.has(srcKey)) srcMap.set(srcKey, { key: srcKey, label: f.src_label || '', bytes: 0, flows: 0 });
        srcMap.get(srcKey).bytes += b;
        srcMap.get(srcKey).flows += fl;

        if (!portMap.has(portKey)) portMap.set(portKey, { key: portKey, label: f.dport_name || '', bytes: 0, flows: 0 });
        portMap.get(portKey).bytes += b;
        portMap.get(portKey).flows += fl;

        if (!dstMap.has(dstKey)) dstMap.set(dstKey, { key: dstKey, label: f.dst_label || '', bytes: 0, flows: 0 });
        dstMap.get(dstKey).bytes += b;
        dstMap.get(dstKey).flows += fl;
    });

    const srcNodes = Array.from(srcMap.values()).sort((a, b) => b.bytes - a.bytes);
    const portNodes = Array.from(portMap.values()).sort((a, b) => b.bytes - a.bytes);
    const dstNodes = Array.from(dstMap.values()).sort((a, b) => b.bytes - a.bytes);

    const maxCount = Math.max(srcNodes.length, portNodes.length, dstNodes.length);
    const svgWidth = Math.max(760, container.clientWidth || 1080);
    const svgHeight = Math.max(270, Math.min(380, maxCount * 30 + 60));
    const topPad = 34;
    const bottomPad = 18;
    const usableHeight = svgHeight - topPad - bottomPad;
    const nodeWidth = 14;
    const leftMargin = 205;
    const rightMargin = 215;
    const colX = [
        leftMargin,
        Math.round(leftMargin + (svgWidth - leftMargin - rightMargin - nodeWidth) / 2),
        svgWidth - rightMargin - nodeWidth
    ];

    const srcColors = ['#6366f1', '#3b82f6', '#0ea5e9', '#38bdf8', '#818cf8', '#60a5fa'];
    const portColors = ['#f59e0b', '#fbbf24', '#a855f7', '#ec4899', '#f97316', '#c084fc'];
    const dstColors = ['#10b981', '#14b8a6', '#ef4444', '#f43f5e', '#34d399', '#fb7185'];

    function layoutColumn(nodes, x, palette) {
        const gap = Math.min(12, Math.max(5, Math.floor(80 / Math.max(1, nodes.length))));
        const totalGap = gap * Math.max(0, nodes.length - 1);
        const availH = Math.max(60, usableHeight - totalGap);
        const sumB = nodes.reduce((s, n) => s + n.bytes, 0) || 1;
        const minH = 12;

        let rawHeights = nodes.map(n => Math.max(minH, (n.bytes / sumB) * availH));
        const sumRaw = rawHeights.reduce((a, b) => a + b, 0);
        if (sumRaw > availH) {
            const scale = availH / sumRaw;
            rawHeights = rawHeights.map(h => Math.max(6, h * scale));
        }

        const totalNodeH = rawHeights.reduce((a, b) => a + b, 0) + totalGap;
        let curY = topPad + Math.max(0, (usableHeight - totalNodeH) / 2);

        nodes.forEach((n, idx) => {
            n.x = x;
            n.y = curY;
            n.h = rawHeights[idx];
            n.color = palette[idx % palette.length];
            n.outOffset = 0;
            n.inOffset = 0;
            curY += n.h + gap;
        });
    }

    layoutColumn(srcNodes, colX[0], srcColors);
    layoutColumn(portNodes, colX[1], portColors);
    layoutColumn(dstNodes, colX[2], dstColors);

    // Aggregate links for Col0->Col1 and Col1->Col2
    const links01Map = new Map();
    const links12Map = new Map();
    topFlows.forEach(f => {
        const b = Math.max(1, Number(f.bytes) || 0);
        const fl = Number(f.flows) || 0;
        const sKey = f.src || 'Unknown';
        const pKey = String(f.dport !== undefined && f.dport !== null ? f.dport : 0);
        const dKey = f.dst || 'Unknown';

        const k01 = `${sKey}__${pKey}`;
        if (!links01Map.has(k01)) links01Map.set(k01, { source: srcMap.get(sKey), target: portMap.get(pKey), bytes: 0, flows: 0 });
        links01Map.get(k01).bytes += b;
        links01Map.get(k01).flows += fl;

        const k12 = `${pKey}__${dKey}`;
        if (!links12Map.has(k12)) links12Map.set(k12, { source: portMap.get(pKey), target: dstMap.get(dKey), bytes: 0, flows: 0 });
        links12Map.get(k12).bytes += b;
        links12Map.get(k12).flows += fl;
    });

    const links01 = Array.from(links01Map.values()).sort((a, b) => (a.source.y - b.source.y) || (a.target.y - b.target.y));
    const links12 = Array.from(links12Map.values()).sort((a, b) => (a.source.y - b.source.y) || (a.target.y - b.target.y));

    let defsHtml = '';
    let linksHtml = '';
    let gradIdx = 0;

    function buildLinkPaths(links, stageLabel) {
        links.forEach(l => {
            const srcH = Math.max(2, (l.bytes / (l.source.bytes || 1)) * l.source.h);
            const tgtH = Math.max(2, (l.bytes / (l.target.bytes || 1)) * l.target.h);
            const y0 = l.source.y + l.source.outOffset;
            const y1 = l.target.y + l.target.inOffset;
            l.source.outOffset += srcH;
            l.target.inOffset += tgtH;

            const x0 = l.source.x + nodeWidth;
            const x1 = l.target.x;
            const mx = (x0 + x1) / 2;

            const pathD = `M ${x0} ${y0} C ${mx} ${y0}, ${mx} ${y1}, ${x1} ${y1} L ${x1} ${y1 + tgtH} C ${mx} ${y1 + tgtH}, ${mx} ${y0 + srcH}, ${x0} ${y0 + srcH} Z`;
            const gId = `sankeyGrad_${gradIdx++}`;
            defsHtml += `
                <linearGradient id="${gId}" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stop-color="${l.source.color}" stop-opacity="0.52"/>
                    <stop offset="100%" stop-color="${l.target.color}" stop-opacity="0.52"/>
                </linearGradient>`;

            const sDesc = l.source.label ? `${l.source.key} (${l.source.label})` : l.source.key;
            const tDesc = l.target.label ? `${l.target.key} (${l.target.label})` : l.target.key;
            const pct = shownBytes > 0 ? ((l.bytes / shownBytes) * 100).toFixed(1) : '0.0';
            const tipText = encodeURIComponent(`<div style="font-weight:700;color:#a5b4fc;margin-bottom:4px;">${stageLabel}</div><div style="font-family:var(--font-mono);">${escapeHtml(sDesc)} ➔ ${escapeHtml(tDesc)}</div><div style="margin-top:4px;color:#34d399;">流量：<strong>${formatBytes(l.bytes)}</strong> (${pct}%) · 連線：<strong>${formatNumber(l.flows)} 筆</strong></div>`);

            linksHtml += `<path d="${pathD}" fill="url(#${gId})" class="sankey-link" data-tip="${tipText}" style="cursor:pointer; transition: opacity 0.18s;" />`;
        });
    }

    buildLinkPaths(links01, '來源 IP ➔ 目的 Port');
    buildLinkPaths(links12, '目的 Port ➔ 目的 IP');

    function truncText(str, maxLen) {
        if (!str) return '';
        return str.length > maxLen ? str.slice(0, maxLen - 1) + '…' : str;
    }

    let nodesHtml = '';
    function buildNodes(nodes, colIndex, filterField) {
        nodes.forEach(n => {
            const pct = shownBytes > 0 ? ((n.bytes / shownBytes) * 100).toFixed(1) : '0.0';
            const colTitle = colIndex === 0 ? '來源 IP' : (colIndex === 1 ? '目的 Port' : '目的 IP');
            const displayMain = colIndex === 1
                ? `Port ${n.key}${n.label ? ` (${truncText(n.label, 12)})` : ''}`
                : n.key;
            const displaySub = colIndex === 1
                ? `${formatBytes(n.bytes)}`
                : (n.label ? `${truncText(n.label, 20)} · ${formatBytes(n.bytes)}` : formatBytes(n.bytes));

            const tipText = encodeURIComponent(`<div style="font-weight:700;color:${n.color};margin-bottom:3px;">${colTitle}</div><div style="font-family:var(--font-mono);font-size:0.84rem;">${escapeHtml(n.key)}${n.label ? ` (${escapeHtml(n.label)})` : ''}</div><div style="margin-top:4px;color:#e2e8f0;">流量：<strong>${formatBytes(n.bytes)}</strong> (${pct}%) · 連線：<strong>${formatNumber(n.flows)} 筆</strong></div><div style="margin-top:4px;font-size:0.72rem;color:#94a3b8;">點擊此節點可即時加入篩選條件</div>`);

            const midY = n.y + n.h / 2;
            let textHtml = '';
            if (colIndex === 0) {
                textHtml = `
                    <text x="${n.x - 8}" y="${midY - (n.h >= 22 ? 3 : -4)}" text-anchor="end" fill="#f1f5f9" font-size="11.5" font-family="var(--font-mono)" font-weight="600">${escapeHtml(truncText(displayMain, 22))}</text>
                    ${n.h >= 22 ? `<text x="${n.x - 8}" y="${midY + 11}" text-anchor="end" fill="#94a3b8" font-size="10">${escapeHtml(displaySub)}</text>` : ''}
                `;
            } else if (colIndex === 1) {
                textHtml = `
                    <text x="${n.x + nodeWidth + 8}" y="${midY - (n.h >= 22 ? 3 : -4)}" text-anchor="start" fill="#fde68a" font-size="11.5" font-family="var(--font-mono)" font-weight="600">${escapeHtml(displayMain)}</text>
                    ${n.h >= 22 ? `<text x="${n.x + nodeWidth + 8}" y="${midY + 11}" text-anchor="start" fill="#94a3b8" font-size="10">${escapeHtml(displaySub)}</text>` : ''}
                `;
            } else {
                textHtml = `
                    <text x="${n.x + nodeWidth + 8}" y="${midY - (n.h >= 22 ? 3 : -4)}" text-anchor="start" fill="#f1f5f9" font-size="11.5" font-family="var(--font-mono)" font-weight="600">${escapeHtml(truncText(displayMain, 22))}</text>
                    ${n.h >= 22 ? `<text x="${n.x + nodeWidth + 8}" y="${midY + 11}" text-anchor="start" fill="#94a3b8" font-size="10">${escapeHtml(displaySub)}</text>` : ''}
                `;
            }

            nodesHtml += `
                <g class="sankey-node" data-field="${filterField}" data-val="${escapeHtml(n.key)}" data-tip="${tipText}" style="cursor:pointer;">
                    <rect x="${n.x}" y="${n.y}" width="${nodeWidth}" height="${n.h}" rx="3" fill="${n.color}" stroke="rgba(255,255,255,0.22)" stroke-width="1"></rect>
                    ${textHtml}
                </g>
            `;
        });
    }

    buildNodes(srcNodes, 0, 'src_ip');
    buildNodes(portNodes, 1, 'dport');
    buildNodes(dstNodes, 2, 'dst_ip');

    container.innerHTML = `
        <svg viewBox="0 0 ${svgWidth} ${svgHeight}" style="width: 100%; height: ${svgHeight}px; min-width: 680px; display: block;">
            <defs>${defsHtml}</defs>
            <text x="${colX[0] + nodeWidth / 2}" y="16" text-anchor="middle" fill="#818cf8" font-size="12" font-weight="700">來源 IP (別名)</text>
            <text x="${colX[1] + nodeWidth / 2}" y="16" text-anchor="middle" fill="#fbbf24" font-size="12" font-weight="700">目的 Port (服務)</text>
            <text x="${colX[2] + nodeWidth / 2}" y="16" text-anchor="middle" fill="#34d399" font-size="12" font-weight="700">目的 IP (Domain / 別名)</text>
            <g class="sankey-links-layer">${linksHtml}</g>
            <g class="sankey-nodes-layer">${nodesHtml}</g>
        </svg>
    `;

    // Bind hover tooltip & node click filter
    const showTip = (e, encodedHtml) => {
        if (!tooltip) return;
        tooltip.innerHTML = decodeURIComponent(encodedHtml);
        tooltip.style.display = 'block';
        const left = Math.min(window.innerWidth - 380, e.clientX + 14);
        const top = Math.min(window.innerHeight - 130, e.clientY + 14);
        tooltip.style.left = `${Math.max(10, left)}px`;
        tooltip.style.top = `${Math.max(10, top)}px`;
    };
    const hideTip = () => {
        if (tooltip) tooltip.style.display = 'none';
    };

    container.querySelectorAll('.sankey-link').forEach(el => {
        el.addEventListener('mouseenter', (e) => {
            container.querySelectorAll('.sankey-link').forEach(o => o.style.opacity = '0.28');
            el.style.opacity = '0.95';
            showTip(e, el.getAttribute('data-tip'));
        });
        el.addEventListener('mousemove', (e) => showTip(e, el.getAttribute('data-tip')));
        el.addEventListener('mouseleave', () => {
            container.querySelectorAll('.sankey-link').forEach(o => o.style.opacity = '1');
            hideTip();
        });
    });

    container.querySelectorAll('.sankey-node').forEach(el => {
        el.addEventListener('mouseenter', (e) => showTip(e, el.getAttribute('data-tip')));
        el.addEventListener('mousemove', (e) => showTip(e, el.getAttribute('data-tip')));
        el.addEventListener('mouseleave', hideTip);
        el.addEventListener('click', () => {
            hideTip();
            applySankeyNodeFilter(el.getAttribute('data-field'), el.getAttribute('data-val'));
        });
    });
}

// Render Anomalous Bar Chart helper
function renderAnomaliesBarChart(canvasId, labels, data, label, bgColor, borderColor, drillMeta) {
    destroyChart(canvasId);
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    const ds = {
        label: label,
        data: data,
        backgroundColor: bgColor,
        borderColor: borderColor,
        borderWidth: 1,
        borderRadius: 4
    };
    if (drillMeta) {
        ds.drillMeta = drillMeta;
    }

    state.charts[canvasId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [ds]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            onClick: (event, elements, chart) => {
                if (!elements || elements.length === 0) return;
                const index = elements[0].index;
                const meta = chart.data.datasets[0].drillMeta;
                if (!meta) return;
                const rawVal = (meta.rawItems && meta.rawItems[index] !== undefined) ? meta.rawItems[index] : chart.data.labels[index];
                showChartContextMenu(event.native || event, meta.itemType, rawVal, meta.viewType, meta.defaultDir);
            },
            onHover: (event, chartElement) => {
                const target = event.native ? event.native.target : (event.target || (event.chart && event.chart.canvas));
                if (target) {
                    target.style.cursor = chartElement[0] ? 'pointer' : 'default';
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: '#1f2937',
                    titleColor: '#f3f4f6',
                    bodyColor: '#d1d5db',
                    borderColor: '#374151',
                    borderWidth: 1,
                    callbacks: {
                        title: function(context) {
                            if (!context || !context.length) return '';
                            const meta = context[0].chart.data.datasets[0].drillMeta;
                            if (meta && meta.itemType === 'alias' && meta.rawItems && meta.rawItems[context[0].dataIndex] !== undefined) {
                                return meta.rawItems[context[0].dataIndex];
                            }
                            return context[0].label;
                        },
                        label: function(context) {
                            let label = ` ${context.dataset.label}: ${formatBytes(context.parsed.y)}`;
                            const meta = context.chart.data.datasets[0].drillMeta;
                            if (meta && meta.flowCounts && meta.flowCounts[context.dataIndex] !== undefined) {
                                label += ` (${formatNumber(meta.flowCounts[context.dataIndex])} flows)`;
                            }
                            return label;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#9ca3af',
                        maxRotation: 45,
                        minRotation: 0,
                        font: {
                            size: 10
                        }
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#9ca3af',
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

// Dynamic Condition Utilities
let _conditionIdCounter = 0;
function genConditionId() {
    return 'cond_' + Date.now() + '_' + (++_conditionIdCounter);
}

// Render dynamic conditions list for 'flow' or 'anomalies'
function renderConditions(viewType) {
    const isFlow = (viewType === 'flow');
    const container = isFlow ? document.getElementById('flow-conditions-list') : document.getElementById('anomalies-conditions-list');
    if (!container) return;

    const conditions = isFlow ? (state.filters.conditions || []) : (state.anomaliesFilters.conditions || []);
    const logic = isFlow ? (state.filters.logic || 'AND') : (state.anomaliesFilters.logic || 'AND');

    // Update active logic buttons in UI
    const logicBtns = document.querySelectorAll(`.btn-logic[data-view="${isFlow ? 'flow' : 'anomalies'}"]`);
    logicBtns.forEach(btn => {
        if (btn.getAttribute('data-logic') === logic) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    if (conditions.length === 0) {
        container.innerHTML = `
            <div class="conditions-empty-tip">
                <i data-lucide="info" style="width: 14px; height: 14px; display: inline-block; vertical-align: -2px; margin-right: 4px;"></i>
                尚未新增任何條件 (可點擊「＋ 新增條件」或直接點擊上方/下方圖表項目以追加為篩選條件)
            </div>
        `;
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
        }
        return;
    }

    let html = '';
    conditions.forEach((cond, idx) => {
        const badgeLabel = (idx === 0) ? '條件 1' : logic;
        const badgeStyle = (idx === 0) ? 'background: rgba(255,255,255,0.08); color: var(--text-secondary);' : '';
        const isIp = ['src_ip', 'dst_ip', 'any_ip'].includes(cond.field);
        const isAlias = ['ip_alias', 'src_alias', 'dst_alias'].includes(cond.field);
        const isPort = ['src_port', 'dst_port', 'any_port'].includes(cond.field);
        const isProto = cond.field === 'proto';

        html += `
            <div class="condition-row" data-id="${cond.id || ''}" data-index="${idx}">
                <span class="condition-badge-logic" style="${badgeStyle}">${badgeLabel}</span>
                <select class="condition-select cond-field" data-index="${idx}">
                    <option value="src_ip" ${cond.field === 'src_ip' ? 'selected' : ''}>來源 IP</option>
                    <option value="dst_ip" ${cond.field === 'dst_ip' ? 'selected' : ''}>目的 IP</option>
                    <option value="any_ip" ${cond.field === 'any_ip' ? 'selected' : ''}>任一端 IP</option>
                    <option value="ip_alias" ${cond.field === 'ip_alias' ? 'selected' : ''}>IP 別名 (任一端)</option>
                    <option value="src_alias" ${cond.field === 'src_alias' ? 'selected' : ''}>來源 IP 別名</option>
                    <option value="dst_alias" ${cond.field === 'dst_alias' ? 'selected' : ''}>目的 IP 別名</option>
                    <option value="src_port" ${cond.field === 'src_port' ? 'selected' : ''}>來源 Port</option>
                    <option value="dst_port" ${cond.field === 'dst_port' ? 'selected' : ''}>目的 Port</option>
                    <option value="any_port" ${cond.field === 'any_port' ? 'selected' : ''}>任一端 Port</option>
                    <option value="proto" ${cond.field === 'proto' ? 'selected' : ''}>通訊協定</option>
                </select>
                <select class="condition-select cond-iptype" data-index="${idx}" style="display: ${isIp ? 'inline-block' : 'none'};">
                    <option value="custom" ${cond.ipType === 'custom' ? 'selected' : ''}>自訂 IP / 前綴</option>
                    <option value="internal" ${cond.ipType === 'internal' ? 'selected' : ''}>私有 IP (Private)</option>
                    <option value="external" ${cond.ipType === 'external' ? 'selected' : ''}>公網 IP (Public)</option>
                </select>
                <input type="${isPort ? 'number' : 'text'}" 
                       class="condition-input cond-val" 
                       data-index="${idx}" 
                       placeholder="${isIp ? '例如: 192.168.1.1 或 10.0.0.0/8' : (isAlias ? '例如: Cloudflare, Core-Router' : (isPort ? '例如: 80, 443' : '例如: TCP 或 6'))}" 
                       value="${escapeHtml(cond.val || '')}" 
                       style="display: ${isIp && cond.ipType !== 'custom' ? 'none' : 'block'};">
                <button type="button" class="btn-remove-condition" data-index="${idx}" title="移除此條件">
                    <i data-lucide="x" style="width: 15px; height: 15px;"></i>
                </button>
            </div>
        `;
    });

    container.innerHTML = html;
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    // Attach row events
    container.querySelectorAll('.cond-field').forEach(sel => {
        sel.addEventListener('change', (e) => {
            const idx = parseInt(e.target.getAttribute('data-index'));
            const field = e.target.value;
            const targetCond = conditions[idx];
            if (targetCond) {
                targetCond.field = field;
                if (['src_ip', 'dst_ip', 'any_ip'].includes(field)) {
                    if (!targetCond.ipType) targetCond.ipType = 'custom';
                }
                renderConditions(viewType);
            }
        });
    });

    container.querySelectorAll('.cond-iptype').forEach(sel => {
        sel.addEventListener('change', (e) => {
            const idx = parseInt(e.target.getAttribute('data-index'));
            const ipType = e.target.value;
            const targetCond = conditions[idx];
            if (targetCond) {
                targetCond.ipType = ipType;
                if (ipType !== 'custom') {
                    targetCond.val = ipType;
                } else if (targetCond.val === 'internal' || targetCond.val === 'external') {
                    targetCond.val = '';
                }
                renderConditions(viewType);
            }
        });
    });

    container.querySelectorAll('.cond-val').forEach(inp => {
        inp.addEventListener('input', (e) => {
            const idx = parseInt(e.target.getAttribute('data-index'));
            const targetCond = conditions[idx];
            if (targetCond) {
                targetCond.val = e.target.value;
            }
        });
        inp.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (isFlow) {
                    applyFiltersFromForm();
                    state.pagination.offset = 0;
                    refreshData();
                } else {
                    applyAnomaliesFiltersFromForm();
                    state.anomaliesPagination.offset = 0;
                    fetchAnomalousReport();
                }
            }
        });
    });

    container.querySelectorAll('.btn-remove-condition').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const idx = parseInt(btn.getAttribute('data-index'));
            conditions.splice(idx, 1);
            renderConditions(viewType);
            if (isFlow) {
                applyFiltersFromForm();
                state.pagination.offset = 0;
                refreshData();
            } else {
                applyAnomaliesFiltersFromForm();
                state.anomaliesPagination.offset = 0;
                fetchAnomalousReport();
            }
        });
    });
}

// Add a new dynamic condition
function addCondition(viewType, field = 'src_ip', val = '', ipType = 'custom') {
    const isFlow = (viewType === 'flow');
    if (isFlow) {
        if (!state.filters.conditions) state.filters.conditions = [];
        state.filters.conditions.push({
            id: genConditionId(),
            field: field,
            ipType: ['src_ip', 'dst_ip', 'any_ip'].includes(field) ? (ipType || 'custom') : '',
            val: String(val || '')
        });
    } else {
        if (!state.anomaliesFilters.conditions) state.anomaliesFilters.conditions = [];
        state.anomaliesFilters.conditions.push({
            id: genConditionId(),
            field: field,
            ipType: ['src_ip', 'dst_ip', 'any_ip'].includes(field) ? (ipType || 'custom') : '',
            val: String(val || '')
        });
    }
    renderConditions(viewType);
    
    // Focus last input
    setTimeout(() => {
        const container = isFlow ? document.getElementById('flow-conditions-list') : document.getElementById('anomalies-conditions-list');
        if (container) {
            const inputs = container.querySelectorAll('.cond-val');
            if (inputs.length > 0) {
                inputs[inputs.length - 1].focus();
            }
        }
    }, 50);
}

// Setup Condition Builders controls
function setupConditionBuilders() {
    document.querySelectorAll('.btn-logic').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const view = btn.getAttribute('data-view');
            const logic = btn.getAttribute('data-logic') || 'AND';
            if (view === 'flow') {
                state.filters.logic = logic;
                renderConditions('flow');
                applyFiltersFromForm();
                state.pagination.offset = 0;
                refreshData();
            } else {
                state.anomaliesFilters.logic = logic;
                renderConditions('anomalies');
                applyAnomaliesFiltersFromForm();
                state.anomaliesPagination.offset = 0;
                fetchAnomalousReport();
            }
        });
    });

    const btnAddFlow = document.getElementById('btn-add-flow-condition');
    if (btnAddFlow) {
        btnAddFlow.addEventListener('click', (e) => {
            e.preventDefault();
            addCondition('flow', 'src_ip', '', 'custom');
        });
    }

    const btnAddAnomalies = document.getElementById('btn-add-anomalies-condition');
    if (btnAddAnomalies) {
        btnAddAnomalies.addEventListener('click', (e) => {
            e.preventDefault();
            addCondition('anomalies', 'src_ip', '', 'custom');
        });
    }
}

// Chart Context Menu Handlers
function showChartContextMenu(nativeEvent, itemType, rawVal, viewType, defaultDir) {
    let menu = document.getElementById('chart-context-menu');
    if (!menu) {
        menu = document.createElement('div');
        menu.id = 'chart-context-menu';
        menu.className = 'chart-context-menu';
        document.body.appendChild(menu);
    }

    let html = '';
    if (itemType === 'ip') {
        const primaryDir = defaultDir || 'any';
        const secDir = primaryDir === 'src' ? 'dst' : (primaryDir === 'dst' ? 'src' : 'any');
        html += `
            <div class="chart-context-menu-item" data-action="filter-ip" data-dir="${primaryDir}" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為${primaryDir === 'src' ? '來源 IP' : (primaryDir === 'dst' ? '目的 IP' : '任一端 IP')} (${rawVal})</span>
            </div>
            ${secDir !== primaryDir ? `
            <div class="chart-context-menu-item" data-action="filter-ip" data-dir="${secDir}" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為${secDir === 'src' ? '來源 IP' : '目的 IP'} (${rawVal})</span>
            </div>
            ` : ''}
            <div class="chart-context-menu-item" data-action="filter-ip" data-dir="any" data-val="${rawVal}">
                <i data-lucide="search"></i> <span>➕ 追加為任一端 IP (${rawVal})</span>
            </div>
        `;
    } else if (itemType === 'port') {
        html += `
            <div class="chart-context-menu-item" data-action="filter-port" data-dir="any" data-val="${rawVal}">
                <i data-lucide="search"></i> <span>➕ 追加為任一端 Port (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-port" data-dir="src" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為來源 Port (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-port" data-dir="dst" data-val="${rawVal}">
                <i data-lucide="plus-circle"></i> <span>➕ 追加為目的 Port (${rawVal})</span>
            </div>
        `;
    } else if (itemType === 'proto') {
        html += `
            <div class="chart-context-menu-item" data-action="filter-proto" data-dir="any" data-val="${rawVal}">
                <i data-lucide="activity"></i> <span>➕ 追加為通訊協定 (${rawVal})</span>
            </div>
        `;
    } else if (itemType === 'alias') {
        html += `
            <div class="chart-context-menu-item" data-action="filter-alias" data-dir="any" data-val="${rawVal}">
                <i data-lucide="tag"></i> <span>➕ 追加為任一端 IP 別名 (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-alias" data-dir="src" data-val="${rawVal}">
                <i data-lucide="arrow-up-right"></i> <span>➕ 追加為來源 IP 別名 (${rawVal})</span>
            </div>
            <div class="chart-context-menu-item" data-action="filter-alias" data-dir="dst" data-val="${rawVal}">
                <i data-lucide="arrow-down-left"></i> <span>➕ 追加為目的 IP 別名 (${rawVal})</span>
            </div>
        `;
    }

    menu.innerHTML = html;
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }

    menu.style.display = 'block';
    const x = nativeEvent.clientX || 100;
    const y = nativeEvent.clientY || 100;
    const menuWidth = 270;
    const menuHeight = menu.offsetHeight || 140;

    const posX = (x + menuWidth > window.innerWidth) ? Math.max(10, x - menuWidth) : x;
    const posY = (y + menuHeight > window.innerHeight) ? Math.max(10, y - menuHeight) : y;
    menu.style.left = `${posX}px`;
    menu.style.top = `${posY}px`;

    menu.querySelectorAll('.chart-context-menu-item').forEach(item => {
        item.onclick = (e) => {
            e.stopPropagation();
            const action = item.getAttribute('data-action');
            const dir = item.getAttribute('data-dir');
            const val = item.getAttribute('data-val');
            hideChartContextMenu();
            applyDrillDownFilter(viewType, action, dir, val);
        };
    });
}

function hideChartContextMenu() {
    const menu = document.getElementById('chart-context-menu');
    if (menu) menu.style.display = 'none';
}

function applyDrillDownFilter(viewType, action, dir, val) {
    let field = 'any_ip';
    if (action === 'filter-ip') {
        field = dir === 'src' ? 'src_ip' : (dir === 'dst' ? 'dst_ip' : 'any_ip');
    } else if (action === 'filter-alias') {
        field = dir === 'src' ? 'src_alias' : (dir === 'dst' ? 'dst_alias' : 'ip_alias');
    } else if (action === 'filter-port') {
        field = dir === 'src' ? 'src_port' : (dir === 'dst' ? 'dst_port' : 'any_port');
    } else if (action === 'filter-proto') {
        field = 'proto';
    }

    if (viewType === 'general') {
        addCondition('flow', field, val, 'custom');
        applyFiltersFromForm();
        state.pagination.offset = 0;
        refreshData();
    } else if (viewType === 'anomalies') {
        addCondition('anomalies', field, val, 'custom');
        applyAnomaliesFiltersFromForm();
        state.anomaliesPagination.offset = 0;
        fetchAnomalousReport();
    }
}

// Fetch Collector Ports Settings
async function fetchCollectorSettings() {
    try {
        const res = await fetch('/api/settings/collector');
        if (!res.ok) throw new Error('Failed to fetch collector settings');
        const data = await res.json();
        if (els.inputSettingNetflowPort) els.inputSettingNetflowPort.value = data.netflow_port || 2055;
        if (els.inputSettingIpfixPort) els.inputSettingIpfixPort.value = data.ipfix_port || 4739;
    } catch (err) {
        showCollectorSettingsStatus(`載入設定失敗: ${err.message}`, 'error');
    }
}

// Save Collector Ports Settings
async function saveCollectorSettings() {
    const nfPort = parseInt(els.inputSettingNetflowPort.value);
    const ipfixPort = parseInt(els.inputSettingIpfixPort.value);

    if (isNaN(nfPort) || nfPort < 1 || nfPort > 65535) {
        showCollectorSettingsStatus('NetFlow Port 必須為 1 至 65535 之間的有效數字', 'error');
        return;
    }
    if (isNaN(ipfixPort) || ipfixPort < 1 || ipfixPort > 65535) {
        showCollectorSettingsStatus('IPFIX Port 必須為 1 至 65535 之間的有效數字', 'error');
        return;
    }
    if (nfPort === ipfixPort) {
        showCollectorSettingsStatus('NetFlow Port 與 IPFIX Port 不可設定為相同 Port 號', 'error');
        return;
    }

    try {
        const res = await fetch('/api/settings/collector', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                netflow_port: nfPort,
                ipfix_port: ipfixPort
            })
        });

        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || '儲存失敗');
        }

        showCollectorSettingsStatus(`✅ 監聽埠設定已成功更新並完成同步！ (NetFlow v9: UDP ${data.netflow_port}, IPFIX: UDP ${data.ipfix_port})`, 'success');
    } catch (err) {
        showCollectorSettingsStatus(`儲存設定失敗: ${err.message}`, 'error');
    }
}

// Show status message for Collector Settings
function showCollectorSettingsStatus(message, type) {
    const el = els.collectorSettingsStatus;
    if (!el) return;

    el.style.display = 'block';
    el.innerText = message;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
}

// ---------------- Authentication Logic ----------------
async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        const data = await res.json();
        if (res.ok && data.authenticated && data.user) {
            state.currentUser = data.user;
            renderCurrentUser(data.user);
            if (els.viewLogin) els.viewLogin.style.display = 'none';
            
            // Check mandatory password change on first login
            if (data.user.must_change_password) {
                if (els.modalMustChangePassword) {
                    els.modalMustChangePassword.classList.add('active');
                }
            }
            return true;
        } else {
            showLoginScreen();
            return false;
        }
    } catch (err) {
        showLoginScreen();
        return false;
    }
}

function showLoginScreen() {
    state.currentUser = null;
    if (els.viewLogin) {
        els.viewLogin.style.display = 'flex';
        if (els.loginUsername) els.loginUsername.focus();
    }
}

function renderCurrentUser(user) {
    if (els.currentUsername) els.currentUsername.innerText = user.username || 'admin';
    if (els.currentUserRole) els.currentUserRole.innerText = user.role === 'admin' ? '系統管理員' : '一般使用者';
    if (els.userAvatarInitial) els.userAvatarInitial.innerText = (user.username || 'A')[0].toUpperCase();
    
    // Control admin-only elements visibility
    if (els.btnTabUsers) {
        els.btnTabUsers.style.display = user.role === 'admin' ? 'flex' : 'none';
    }
}

async function handleLogin() {
    const username = els.loginUsername.value.trim();
    const password = els.loginPassword.value;
    if (!username || !password) {
        showLoginError('請輸入帳號與密碼');
        return;
    }

    els.loginErrorMessage.style.display = 'none';
    els.btnDoLogin.disabled = true;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok) {
            throw new Error(data.detail || '登入失敗');
        }

        state.currentUser = data.user;
        renderCurrentUser(data.user);
        els.loginPassword.value = '';
        els.viewLogin.style.display = 'none';

        if (data.user.must_change_password && els.modalMustChangePassword) {
            els.modalMustChangePassword.classList.add('active');
        } else {
            // Proceed to app
            fetchExporterDropdown();
            fetchPortAliases();
            fetchIpAliases();
            switchTab('anomalies');
        }
    } catch (err) {
        showLoginError(err.message);
    } finally {
        els.btnDoLogin.disabled = false;
    }
}

function showLoginError(msg) {
    if (els.loginErrorMessage) {
        els.loginErrorMessage.innerText = msg;
        els.loginErrorMessage.style.display = 'block';
    }
}

async function handleLogout() {
    if (!confirm('您確定要登出系統嗎？')) return;
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    showLoginScreen();
}

function openChangePwdModal() {
    if (els.modalChangePassword) {
        els.formChangeOwnPassword.reset();
        if (els.changePwdError) els.changePwdError.style.display = 'none';
        els.modalChangePassword.classList.add('active');
    }
}

function closeChangePwdModal() {
    if (els.modalChangePassword) els.modalChangePassword.classList.remove('active');
}

async function submitChangeOwnPassword() {
    const old_password = els.inputCurrentPwd.value;
    const new_password = els.inputNewOwnPwd.value;
    const confirm_pwd = els.inputNewOwnPwdConfirm.value;

    if (new_password !== confirm_pwd) {
        showChangePwdError('兩次輸入的新密碼不一致！');
        return;
    }
    if (new_password.length < 6) {
        showChangePwdError('新密碼長度至少需為 6 個字元！');
        return;
    }

    try {
        const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_password, new_password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '修改失敗');
        
        alert('密碼修改成功！');
        closeChangePwdModal();
    } catch (err) {
        showChangePwdError(err.message);
    }
}

function showChangePwdError(msg) {
    if (els.changePwdError) {
        els.changePwdError.innerText = msg;
        els.changePwdError.style.display = 'block';
    }
}

async function submitForceChangePassword() {
    const old_password = els.inputForceOldPwd.value;
    const new_password = els.inputForceNewPwd.value;
    const confirm_pwd = els.inputForceNewPwdConfirm.value;

    if (new_password !== confirm_pwd) {
        showForcePwdError('兩次輸入的新密碼不一致！');
        return;
    }
    if (new_password.length < 6) {
        showForcePwdError('新密碼長度至少需為 6 個字元！');
        return;
    }

    try {
        const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_password, new_password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '更新失敗');
        
        alert('密碼已成功設定！歡迎使用 Super Flow 系統。');
        if (els.modalMustChangePassword) {
            els.modalMustChangePassword.classList.remove('active');
        }
        fetchExporterDropdown();
        fetchPortAliases();
        fetchIpAliases();
        switchTab('anomalies');
    } catch (err) {
        showForcePwdError(err.message);
    }
}

function showForcePwdError(msg) {
    if (els.forcePwdError) {
        els.forcePwdError.innerText = msg;
        els.forcePwdError.style.display = 'block';
    }
}

// ---------------- Retention Settings & Schedule Logic ----------------
async function fetchRetentionSettings() {
    try {
        const res = await fetch('/api/settings/retention');
        if (!res.ok) throw new Error('讀取保留設定失敗');
        const data = await res.json();
        
        if (els.inputRetentionDays) els.inputRetentionDays.value = data.retention_days;
        if (els.inputRetentionTime) els.inputRetentionTime.value = data.schedule_time;
        if (els.selectRetentionEnabled) els.selectRetentionEnabled.value = data.enabled ? '1' : '0';
        if (els.retentionLastRunTime) els.retentionLastRunTime.innerText = data.last_run || '尚未執行';
        if (els.retentionNextRunTime) els.retentionNextRunTime.innerText = data.next_run || '-';
        if (els.retentionLastMessage) els.retentionLastMessage.innerText = data.last_message || '-';
        
        if (els.retentionStatusBadge) {
            if (data.enabled) {
                els.retentionStatusBadge.className = 'badge badge-success';
                els.retentionStatusBadge.innerText = '排程監控中';
            } else {
                els.retentionStatusBadge.className = 'badge badge-secondary';
                els.retentionStatusBadge.innerText = '排程已停用';
            }
        }
    } catch (err) {
        showRetentionAlert(`無法載入資料保留政策設定: ${err.message}`, 'error');
    }
}

async function saveRetentionSettings() {
    const retention_days = parseInt(els.inputRetentionDays.value, 10);
    const schedule_time = els.inputRetentionTime.value;
    const enabled = els.selectRetentionEnabled.value === '1';

    if (isNaN(retention_days) || retention_days < 1) {
        showRetentionAlert('保留天數必須大於 0 天', 'error');
        return;
    }

    try {
        const res = await fetch('/api/settings/retention', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ retention_days, schedule_time, enabled })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '儲存失敗');
        
        showRetentionAlert(data.message || '資料保留政策更新成功！', 'success');
        fetchRetentionSettings();
    } catch (err) {
        showRetentionAlert(err.message, 'error');
    }
}

async function runRetentionNow() {
    if (!confirm(`確定要立即觸發定時排程清理作業嗎？系統將立即清除超過保留天數的 Flow 歷史資料。`)) {
        return;
    }

    showRetentionAlert('正在執行排程清理作業...', 'info');
    try {
        const res = await fetch('/api/flows/cleanup/execute-retention', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '執行失敗');

        showRetentionAlert(data.message || '排程清理已成功完成！', 'success');
        fetchRetentionSettings();
    } catch (err) {
        showRetentionAlert(`執行失敗: ${err.message}`, 'error');
    }
}

function showRetentionAlert(msg, type) {
    const el = els.retentionStatusAlert;
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else if (type === 'error') {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(59, 130, 246, 0.15)';
        el.style.color = '#60a5fa';
        el.style.border = '1px solid rgba(59, 130, 246, 0.3)';
    }
}

// ---------------- Collector Allowed CIDRs Logic ----------------
async function fetchCollectorCidrs() {
    const tbody = els.collectorCidrsTbody;
    if (!tbody) return;

    try {
        const res = await fetch('/api/settings/collector/cidrs');
        if (!res.ok) throw new Error('無法讀取白名單');
        const list = await res.json();

        if (list.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-muted" style="padding: 24px 0;">
                        目前未設定白名單（系統預設接收來自所有來源 Exporter 的流量封包）。
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = '';
        list.forEach(item => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            tr.innerHTML = `
                <td style="padding: 10px 14px; font-family: var(--font-mono); font-weight: 600; color: #818cf8;">${item.cidr}</td>
                <td style="padding: 10px 14px; color: var(--text-secondary);">${item.description || '-'}</td>
                <td style="padding: 10px 14px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">${item.created_at || '-'}</td>
                <td style="padding: 10px 14px; text-align: center;">
                    <button class="btn-del-cidr" data-id="${item.id}" data-cidr="${item.cidr}" style="background: none; border: none; color: var(--color-danger); cursor: pointer; padding: 4px 8px; border-radius: 4px;">
                        <i data-lucide="trash-2" style="width: 15px; height: 15px;"></i>
                    </button>
                </td>
            `;
            const btnDel = tr.querySelector('.btn-del-cidr');
            btnDel.addEventListener('click', () => deleteCollectorCidr(item.id, item.cidr));
            tbody.appendChild(tr);
        });

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center text-danger" style="padding: 20px 0;">讀取白名單失敗: ${err.message}</td></tr>`;
    }
}

async function addCollectorCidr() {
    const cidr = els.inputNewCollectorCidr.value.trim();
    const description = els.inputNewCollectorCidrDesc.value.trim();
    if (!cidr) return;

    try {
        const res = await fetch('/api/settings/collector/cidrs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr, description })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '新增失敗');

        showCollectorCidrStatus(data.message, 'success');
        els.inputNewCollectorCidr.value = '';
        els.inputNewCollectorCidrDesc.value = '';
        fetchCollectorCidrs();
    } catch (err) {
        showCollectorCidrStatus(err.message, 'error');
    }
}

async function deleteCollectorCidr(id, cidr) {
    if (!confirm(`確定要將 '${cidr}' 從收集器允許接收白名單中移除嗎？`)) return;
    try {
        const res = await fetch(`/api/settings/collector/cidrs/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '刪除失敗');

        showCollectorCidrStatus(`已移除白名單網段 '${cidr}'`, 'success');
        fetchCollectorCidrs();
    } catch (err) {
        showCollectorCidrStatus(err.message, 'error');
    }
}

function showCollectorCidrStatus(msg, type) {
    const el = els.collectorCidrsStatus;
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ---------------- User Management Logic (Admin) ----------------
async function fetchUsersList() {
    const tbody = els.usersTbody;
    if (!tbody) return;

    try {
        const res = await fetch('/api/users');
        if (!res.ok) {
            if (res.status === 403) {
                tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 30px 0;">權限不足，僅系統管理員可檢視與管理帳號清單。</td></tr>`;
                return;
            }
            throw new Error('讀取使用者清單失敗');
        }
        const users = await res.json();
        tbody.innerHTML = '';

        users.forEach(u => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid var(--border-color)';
            
            const roleBadge = u.role === 'admin' 
                ? `<span class="badge badge-primary">系統管理員</span>` 
                : `<span class="badge badge-secondary">一般使用者</span>`;
                
            const statusBadge = u.is_active 
                ? `<span class="badge badge-success">正常啟用</span>` 
                : `<span class="badge badge-warning" style="color: #f87171;">已停用</span>`;
                
            const pwdBadge = u.must_change_password 
                ? `<span class="badge badge-warning">首次登入須修改</span>` 
                : `<span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">已設定</span>`;

            tr.innerHTML = `
                <td style="padding: 12px 14px; font-weight: 600; color: var(--text-primary);">${u.username}</td>
                <td style="padding: 12px 14px;">${roleBadge}</td>
                <td style="padding: 12px 14px;">${statusBadge}</td>
                <td style="padding: 12px 14px;">${pwdBadge}</td>
                <td style="padding: 12px 14px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">${u.last_login || '從未登入'}</td>
                <td style="padding: 12px 14px; font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">${u.created_at || '-'}</td>
                <td style="padding: 12px 14px; text-align: center;">
                    <div style="display: inline-flex; align-items: center; gap: 6px;">
                        <button class="btn-toggle-active" data-id="${u.id}" data-active="${u.is_active}" data-uname="${u.username}" title="${u.is_active ? '停用帳號' : '啟用帳號'}" style="background: none; border: none; cursor: pointer; padding: 4px; border-radius: 4px; color: ${u.is_active ? '#fbbf24' : '#34d399'};">
                            <i data-lucide="${u.is_active ? 'pause-circle' : 'play-circle'}" style="width: 16px; height: 16px;"></i>
                        </button>
                        <button class="btn-reset-user-pwd" data-id="${u.id}" data-uname="${u.username}" title="重設密碼" style="background: none; border: none; cursor: pointer; padding: 4px; border-radius: 4px; color: #818cf8;">
                            <i data-lucide="key" style="width: 16px; height: 16px;"></i>
                        </button>
                        <button class="btn-del-user" data-id="${u.id}" data-uname="${u.username}" title="刪除帳號" style="background: none; border: none; cursor: pointer; padding: 4px; border-radius: 4px; color: #f87171;" ${u.username === 'admin' ? 'disabled style="opacity: 0.3; cursor: not-allowed;"' : ''}>
                            <i data-lucide="trash-2" style="width: 16px; height: 16px;"></i>
                        </button>
                    </div>
                </td>
            `;

            const btnToggle = tr.querySelector('.btn-toggle-active');
            btnToggle.addEventListener('click', () => toggleUserActive(u.id, u.is_active, u.username));

            const btnReset = tr.querySelector('.btn-reset-user-pwd');
            btnReset.addEventListener('click', () => openResetPasswordModal(u.id, u.username));

            const btnDel = tr.querySelector('.btn-del-user');
            if (u.username !== 'admin') {
                btnDel.addEventListener('click', () => deleteUser(u.id, u.username));
            }

            tbody.appendChild(tr);
        });

        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-danger" style="padding: 20px 0;">載入使用者失敗: ${err.message}</td></tr>`;
    }
}

function openAddUserModal() {
    if (els.modalAddUser) {
        els.formAddUser.reset();
        if (els.addUserError) els.addUserError.style.display = 'none';
        els.modalAddUser.classList.add('active');
        if (els.inputNewUserName) els.inputNewUserName.focus();
    }
}

function closeAddUserModal() {
    if (els.modalAddUser) els.modalAddUser.classList.remove('active');
}

async function submitCreateUser() {
    const username = els.inputNewUserName.value.trim();
    const password = els.inputNewUserPassword.value;
    const role = els.selectNewUserRole.value;

    try {
        const res = await fetch('/api/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '建立使用者失敗');

        closeAddUserModal();
        showUserStatusMessage(data.message || `使用者 '${username}' 建立成功`, 'success');
        fetchUsersList();
    } catch (err) {
        if (els.addUserError) {
            els.addUserError.innerText = err.message;
            els.addUserError.style.display = 'block';
        }
    }
}

async function toggleUserActive(userId, currentActive, username) {
    const targetState = !currentActive;
    const actionText = targetState ? '啟用' : '停用';
    if (!confirm(`確定要${actionText}使用者 '${username}' 嗎？`)) return;

    try {
        const res = await fetch(`/api/users/${userId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ is_active: targetState })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '更新狀態失敗');

        showUserStatusMessage(`已成功${actionText}使用者 '${username}'`, 'success');
        fetchUsersList();
    } catch (err) {
        showUserStatusMessage(err.message, 'error');
    }
}

function openResetPasswordModal(userId, username) {
    if (els.modalResetUserPassword) {
        els.resetTargetUserId.value = userId;
        els.resetTargetUsername.innerText = username;
        els.formResetUserPassword.reset();
        if (els.resetPwdError) els.resetPwdError.style.display = 'none';
        els.modalResetUserPassword.classList.add('active');
        if (els.inputAdminNewPwd) els.inputAdminNewPwd.focus();
    }
}

function closeResetPwdModal() {
    if (els.modalResetUserPassword) els.modalResetUserPassword.classList.remove('active');
}

async function submitResetUserPassword() {
    const userId = els.resetTargetUserId.value;
    const new_password = els.inputAdminNewPwd.value;

    try {
        const res = await fetch(`/api/users/${userId}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_password })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '重設密碼失敗');

        closeResetPwdModal();
        showUserStatusMessage(data.message || '密碼已成功重設', 'success');
        fetchUsersList();
    } catch (err) {
        if (els.resetPwdError) {
            els.resetPwdError.innerText = err.message;
            els.resetPwdError.style.display = 'block';
        }
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`確定要刪除使用者 '${username}' 嗎？此操作將無法復原。`)) return;

    try {
        const res = await fetch(`/api/users/${userId}`, { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '刪除失敗');

        showUserStatusMessage(data.message || `已成功刪除使用者 '${username}'`, 'success');
        fetchUsersList();
    } catch (err) {
        showUserStatusMessage(err.message, 'error');
    }
}

function showUserStatusMessage(msg, type) {
    const el = els.usersStatusMessage;
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// ============================================================================
// Smart Situational Threat Diagnostics + AtheNAC Integration (3-Tier Flow)
// ============================================================================
const diagState = {
    mode: 'smart', // 'smart' | 'legacy'
    timeRange: 'custom', // 'custom' | 'today' | '24h' | '7d' | 'all'
    targetDate: '2026-11-17', // YYYY-MM-DD
    targetYear: 2026,
    targetMonth: 11,
    targetDay: 17,
    startTime: '00:00',
    endTime: '23:59',
    timeLabel: '2026-11-17 全日時段',
    severity: '', // Tier 1: Default to '' (全部風險異常)
    scenarioId: null, // Tier 2: Specific scenario filter
    scenarioName: '',
    category: '',
    hostIp: '',
    events: [],
    rawCharts: {},
    summary: {},
    scenarios: []
};

function getDaysInMonth(year, month) {
    return new Date(year, month, 0).getDate();
}

function initDiagDatePicker() {
    const selYear = document.getElementById('diag-select-year');
    const selMonth = document.getElementById('diag-select-month');
    const selDay = document.getElementById('diag-select-day');
    const nativeDateInput = document.getElementById('diag-native-date-input');
    const btnCalendar = document.getElementById('btn-diag-calendar-trigger');
    const timeRangeSel = document.getElementById('diag-time-range');
    const dateContainer = document.getElementById('diag-custom-date-container');
    const startTimeInput = document.getElementById('diag-start-time');
    const endTimeInput = document.getElementById('diag-end-time');

    if (!selYear || !selMonth || !selDay) return;

    function updateDateContainerVisibility() {
        if (!dateContainer || !timeRangeSel) return;
        if (timeRangeSel.value === 'custom') {
            dateContainer.style.display = 'inline-flex';
        } else {
            dateContainer.style.display = 'none';
        }
    }

    // Available years: 2023 to (currentYear + 1)
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1;
    const currentDay = now.getDate();

    // Populate Year options
    selYear.innerHTML = '';
    for (let y = currentYear - 3; y <= currentYear + 1; y++) {
        const opt = document.createElement('option');
        opt.value = y;
        opt.textContent = `${y}`;
        selYear.appendChild(opt);
    }

    // Populate Month options (01 ~ 12)
    selMonth.innerHTML = '';
    for (let m = 1; m <= 12; m++) {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = String(m).padStart(2, '0');
        selMonth.appendChild(opt);
    }

    function updateDayOptions(year, month, targetDay) {
        const daysCount = getDaysInMonth(year, month);
        selDay.innerHTML = '';
        for (let d = 1; d <= daysCount; d++) {
            const opt = document.createElement('option');
            opt.value = d;
            opt.textContent = String(d).padStart(2, '0');
            selDay.appendChild(opt);
        }
        if (targetDay && targetDay <= daysCount) {
            selDay.value = targetDay;
        } else if (targetDay && targetDay > daysCount) {
            selDay.value = daysCount;
        }
    }

    // Determine initial values from localStorage or defaults
    let initYear = parseInt(localStorage.getItem('diag_saved_year')) || currentYear;
    let initMonth = parseInt(localStorage.getItem('diag_saved_month')) || currentMonth;
    let initDay = parseInt(localStorage.getItem('diag_saved_day')) || currentDay;
    let initPreset = localStorage.getItem('diag_saved_preset') || 'custom';
    let initDate = localStorage.getItem('diag_saved_date');
    let initStartTime = localStorage.getItem('diag_saved_start_time') || '00:00';
    let initEndTime = localStorage.getItem('diag_saved_end_time') || '23:59';

    if (initDate && /^\d{4}-\d{2}-\d{2}$/.test(initDate)) {
        const parts = initDate.split('-').map(Number);
        initYear = parts[0];
        initMonth = parts[1];
        initDay = parts[2];
    }

    selYear.value = initYear;
    selMonth.value = initMonth;
    updateDayOptions(initYear, initMonth, initDay);
    selDay.value = initDay;

    const formattedDate = `${initYear}-${String(initMonth).padStart(2, '0')}-${String(initDay).padStart(2, '0')}`;
    if (nativeDateInput) nativeDateInput.value = formattedDate;
    if (timeRangeSel) timeRangeSel.value = initPreset;
    if (startTimeInput) startTimeInput.value = initStartTime;
    if (endTimeInput) endTimeInput.value = initEndTime;

    diagState.targetYear = initYear;
    diagState.targetMonth = initMonth;
    diagState.targetDay = initDay;
    diagState.targetDate = formattedDate;
    diagState.timeRange = initPreset;
    diagState.startTime = initStartTime;
    diagState.endTime = initEndTime;

    updateDateContainerVisibility();

    function onDateChanged(triggerFetch = true) {
        const y = parseInt(selYear.value);
        const m = parseInt(selMonth.value);
        const curDay = parseInt(selDay.value);
        updateDayOptions(y, m, curDay);
        const d = parseInt(selDay.value);

        const dStr = `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
        if (nativeDateInput) nativeDateInput.value = dStr;

        diagState.targetYear = y;
        diagState.targetMonth = m;
        diagState.targetDay = d;
        diagState.targetDate = dStr;
        diagState.timeRange = 'custom';
        if (timeRangeSel) timeRangeSel.value = 'custom';
        updateDateContainerVisibility();

        saveDiagDatePreference(y, m, d, 'custom', dStr, diagState.startTime, diagState.endTime);

        if (triggerFetch) {
            const btnRefresh = document.getElementById('btn-refresh-diagnostics');
            executeRefreshWithFeedback(
                btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                `已載入 ${dStr} 智慧情境診斷資料。`
            );
        }
    }

    selYear.addEventListener('change', () => onDateChanged(true));
    selMonth.addEventListener('change', () => onDateChanged(true));
    selDay.addEventListener('change', () => onDateChanged(true));

    if (startTimeInput) {
        startTimeInput.addEventListener('change', () => {
            diagState.startTime = startTimeInput.value || '00:00';
            saveDiagDatePreference(diagState.targetYear, diagState.targetMonth, diagState.targetDay, diagState.timeRange, diagState.targetDate, diagState.startTime, diagState.endTime);
            const btnRefresh = document.getElementById('btn-refresh-diagnostics');
            executeRefreshWithFeedback(
                btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                `已更新指定時段 (${diagState.startTime} ~ ${diagState.endTime})。`
            );
        });
    }

    if (endTimeInput) {
        endTimeInput.addEventListener('change', () => {
            diagState.endTime = endTimeInput.value || '23:59';
            saveDiagDatePreference(diagState.targetYear, diagState.targetMonth, diagState.targetDay, diagState.timeRange, diagState.targetDate, diagState.startTime, diagState.endTime);
            const btnRefresh = document.getElementById('btn-refresh-diagnostics');
            executeRefreshWithFeedback(
                btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                `已更新指定時段 (${diagState.startTime} ~ ${diagState.endTime})。`
            );
        });
    }

    if (btnCalendar && nativeDateInput) {
        btnCalendar.addEventListener('click', () => {
            try {
                if (typeof nativeDateInput.showPicker === 'function') {
                    nativeDateInput.showPicker();
                } else {
                    nativeDateInput.focus();
                    nativeDateInput.click();
                }
            } catch (e) {
                nativeDateInput.focus();
                nativeDateInput.click();
            }
        });
    }

    if (nativeDateInput) {
        nativeDateInput.addEventListener('change', () => {
            if (!nativeDateInput.value) return;
            const parts = nativeDateInput.value.split('-').map(Number);
            if (parts.length === 3) {
                selYear.value = parts[0];
                selMonth.value = parts[1];
                updateDayOptions(parts[0], parts[1], parts[2]);
                selDay.value = parts[2];
                onDateChanged(true);
            }
        });
    }

    fetchDiagDatePreferenceFromServer();
}

async function fetchDiagDatePreferenceFromServer() {
    try {
        const res = await fetch('/api/anomalies/preference');
        if (!res.ok) return;
        const data = await res.json();
        const startTimeInput = document.getElementById('diag-start-time');
        const endTimeInput = document.getElementById('diag-end-time');
        const timeRangeSel = document.getElementById('diag-time-range');
        const dateContainer = document.getElementById('diag-custom-date-container');

        if (data.start_time && startTimeInput) {
            startTimeInput.value = data.start_time;
            diagState.startTime = data.start_time;
            localStorage.setItem('diag_saved_start_time', data.start_time);
        }
        if (data.end_time && endTimeInput) {
            endTimeInput.value = data.end_time;
            diagState.endTime = data.end_time;
            localStorage.setItem('diag_saved_end_time', data.end_time);
        }

        if (data.date && /^\d{4}-\d{2}-\d{2}$/.test(data.date)) {
            const localDate = localStorage.getItem('diag_saved_date');
            if (!localDate) {
                const parts = data.date.split('-').map(Number);
                const selYear = document.getElementById('diag-select-year');
                const selMonth = document.getElementById('diag-select-month');
                const selDay = document.getElementById('diag-select-day');
                if (selYear) selYear.value = parts[0];
                if (selMonth) selMonth.value = parts[1];
                if (selDay) {
                    const days = getDaysInMonth(parts[0], parts[1]);
                    selDay.innerHTML = '';
                    for (let d = 1; d <= days; d++) {
                        const opt = document.createElement('option');
                        opt.value = d;
                        opt.textContent = String(d).padStart(2, '0');
                        selDay.appendChild(opt);
                    }
                    selDay.value = parts[2];
                }
                if (timeRangeSel && data.preset) timeRangeSel.value = data.preset;

                diagState.targetYear = parts[0];
                diagState.targetMonth = parts[1];
                diagState.targetDay = parts[2];
                diagState.targetDate = data.date;
                diagState.timeRange = data.preset || 'custom';

                localStorage.setItem('diag_saved_year', String(parts[0]));
                localStorage.setItem('diag_saved_month', String(parts[1]));
                localStorage.setItem('diag_saved_day', String(parts[2]));
                localStorage.setItem('diag_saved_date', data.date);
                localStorage.setItem('diag_saved_preset', data.preset || 'custom');

                if (dateContainer && timeRangeSel) {
                    dateContainer.style.display = (timeRangeSel.value === 'custom') ? 'inline-flex' : 'none';
                }

                fetchSmartDiagnostics();
            }
        }
        if (dateContainer && timeRangeSel) {
            dateContainer.style.display = (timeRangeSel.value === 'custom') ? 'inline-flex' : 'none';
        }
    } catch (e) {
        // Ignore network / offline error
    }
}

function saveDiagDatePreference(year, month, day, preset, dateStr, startTime = '00:00', endTime = '23:59') {
    // 1. Client-side localStorage
    try {
        localStorage.setItem('diag_saved_year', String(year));
        localStorage.setItem('diag_saved_month', String(month));
        localStorage.setItem('diag_saved_day', String(day));
        localStorage.setItem('diag_saved_date', dateStr);
        localStorage.setItem('diag_saved_preset', preset);
        localStorage.setItem('diag_saved_start_time', startTime);
        localStorage.setItem('diag_saved_end_time', endTime);
    } catch (e) {}

    // 2. Server-side preference persistence
    fetch('/api/anomalies/preference', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            year: year,
            month: month,
            day: day,
            date: dateStr,
            preset: preset,
            start_time: startTime,
            end_time: endTime
        })
    }).catch(err => console.warn('Failed to save preference to server:', err));
}

function initSmartDiagnosticsUI() {
    const btnSmart = document.getElementById('btn-anomalies-mode-smart');
    const btnLegacy = document.getElementById('btn-anomalies-mode-legacy');
    const timeSel = document.getElementById('diag-time-range');
    const btnRefresh = document.getElementById('btn-refresh-diagnostics');
    const btnOpenRules = document.getElementById('btn-open-scenario-rules');
    const btnClearFilter = document.getElementById('btn-diag-clear-filter');
    const btnBackToSmart = document.getElementById('btn-back-to-smart-diag');
    const btnClearScenario = document.getElementById('btn-tier2-clear-scenario');
    const statusFilterSel = document.getElementById('diag-filter-status');

    if (statusFilterSel) {
        statusFilterSel.addEventListener('change', () => {
            diagState.incidentStatus = statusFilterSel.value || '';
            renderFilteredEquipmentList();
        });
    }
    const btnResetTier3Cols = document.getElementById('btn-reset-tier3-cols');
    if (btnResetTier3Cols) {
        btnResetTier3Cols.addEventListener('click', () => {
            resetTier3Columns();
        });
    }
    renderTier3TableHeader();

    if (btnSmart) btnSmart.addEventListener('click', () => switchAnomaliesMode('smart'));
    if (btnLegacy) btnLegacy.addEventListener('click', () => switchAnomaliesMode('legacy'));
    if (btnBackToSmart) btnBackToSmart.addEventListener('click', () => switchAnomaliesMode('smart'));

    // Initialize Year / Month / Day Date Picker
    initDiagDatePicker();

    if (timeSel) {
        timeSel.addEventListener('change', () => {
            const val = timeSel.value;
            diagState.timeRange = val;
            const dateContainer = document.getElementById('diag-custom-date-container');
            if (dateContainer) {
                dateContainer.style.display = (val === 'custom') ? 'inline-flex' : 'none';
            }
            if (val === 'today') {
                const now = new Date();
                const y = now.getFullYear();
                const m = now.getMonth() + 1;
                const d = now.getDate();
                const dateStr = `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
                diagState.targetYear = y;
                diagState.targetMonth = m;
                diagState.targetDay = d;
                diagState.targetDate = dateStr;

                const selYear = document.getElementById('diag-select-year');
                const selMonth = document.getElementById('diag-select-month');
                const selDay = document.getElementById('diag-select-day');
                if (selYear) selYear.value = y;
                if (selMonth) selMonth.value = m;
                if (selDay) selDay.value = d;
                saveDiagDatePreference(y, m, d, 'today', dateStr, diagState.startTime, diagState.endTime);
            } else if (val === 'custom') {
                const selYear = document.getElementById('diag-select-year');
                const selMonth = document.getElementById('diag-select-month');
                const selDay = document.getElementById('diag-select-day');
                const y = parseInt(selYear?.value || '2026');
                const m = parseInt(selMonth?.value || '11');
                const d = parseInt(selDay?.value || '17');
                const dateStr = `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
                diagState.targetYear = y;
                diagState.targetMonth = m;
                diagState.targetDay = d;
                diagState.targetDate = dateStr;
                saveDiagDatePreference(y, m, d, 'custom', dateStr, diagState.startTime, diagState.endTime);
            } else {
                saveDiagDatePreference(diagState.targetYear || 2026, diagState.targetMonth || 11, diagState.targetDay || 17, val, diagState.targetDate || '2026-11-17', diagState.startTime, diagState.endTime);
            }
            executeRefreshWithFeedback(
                btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                '已切換診斷時段並完成情境分析。'
            );
        });
    }
    if (btnRefresh) {
        btnRefresh.addEventListener('click', (e) => {
            e.preventDefault();
            executeRefreshWithFeedback(
                btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                '智慧情境診斷已完成，已載入最新流量與設備威脅狀態。'
            );
        });
    }
    if (btnClearFilter) {
        btnClearFilter.addEventListener('click', () => {
            diagState.severity = '';
            diagState.scenarioId = null;
            diagState.scenarioName = '';
            diagState.category = '';
            diagState.hostIp = '';
            diagState.incidentStatus = '';
            const statusSel = document.getElementById('diag-filter-status');
            if (statusSel) statusSel.value = '';
            executeRefreshWithFeedback(
                btnRefresh,
                () => fetchSmartDiagnostics(),
                '診斷完成',
                '已清除所有篩選條件並重設智慧情境診斷。'
            );
        });
    }
    if (btnClearScenario) {
        btnClearScenario.addEventListener('click', () => {
            diagState.scenarioId = null;
            diagState.scenarioName = '';
            updateTierBreadcrumbs();
            renderTier2Charts();
            renderFilteredEquipmentList();
        });
    }

    // Tier 1 KPI Cards click handler
    document.querySelectorAll('.diag-kpi-card').forEach(card => {
        card.addEventListener('click', () => {
            const sev = card.dataset.severity || '';
            diagState.severity = sev;
            diagState.scenarioId = null;
            diagState.scenarioName = '';
            diagState.category = '';
            diagState.hostIp = '';
            updateTier1Cards(diagState.summary);
            updateTierBreadcrumbs();
            renderTier2Charts();
            renderFilteredEquipmentList();
        });
    });

    // Playbook Modal bindings
    const btnClosePlaybook = document.getElementById('btn-close-playbook-modal');
    const btnClosePlaybookFooter = document.getElementById('btn-playbook-close-footer');
    const btnCopyPlaybook = document.getElementById('btn-playbook-copy');
    if (btnClosePlaybook) btnClosePlaybook.addEventListener('click', closePlaybookModal);
    if (btnClosePlaybookFooter) btnClosePlaybookFooter.addEventListener('click', closePlaybookModal);
    if (btnCopyPlaybook) btnCopyPlaybook.addEventListener('click', copyPlaybookReport);

    // Scenario Rules Modal bindings
    if (btnOpenRules) btnOpenRules.addEventListener('click', openScenarioRulesModal);
    const btnCloseSc = document.getElementById('btn-close-scenario-modal');
    if (btnCloseSc) btnCloseSc.addEventListener('click', closeScenarioRulesModal);
    const btnResetScDefaults = document.getElementById('btn-reset-default-scenarios');
    if (btnResetScDefaults) btnResetScDefaults.addEventListener('click', resetDefaultScenarios);
    const btnResetScForm = document.getElementById('btn-sc-reset-form');
    if (btnResetScForm) btnResetScForm.addEventListener('click', clearScenarioForm);

    const formSc = document.getElementById('form-scenario-rule');
    if (formSc) {
        formSc.addEventListener('submit', (e) => {
            e.preventDefault();
            submitScenarioForm();
        });
    }

    document.querySelectorAll('.scenario-preset-btn').forEach(btn => {
        btn.addEventListener('click', () => applyScenarioPreset(btn.dataset.preset));
    });

    // AtheNAC Settings bindings
    const formAthenac = document.getElementById('form-athenac-settings');
    if (formAthenac) {
        formAthenac.addEventListener('submit', (e) => {
            e.preventDefault();
            saveAthenacSettings();
        });
    }
    const btnTestAthenac = document.getElementById('btn-test-athenac');
    if (btnTestAthenac) btnTestAthenac.addEventListener('click', testAthenacConnection);

    // Threat Intel API Settings & Cache bindings
    const formThreatIntel = document.getElementById('form-threat-intel-settings');
    if (formThreatIntel) {
        formThreatIntel.addEventListener('submit', (e) => {
            e.preventDefault();
            saveThreatIntelSettings();
        });
    }
    const btnTestIntel = document.getElementById('btn-test-threat-intel');
    if (btnTestIntel) btnTestIntel.addEventListener('click', testThreatIntelConnection);

    const btnManualIntelQuery = document.getElementById('btn-manual-intel-query');
    if (btnManualIntelQuery) btnManualIntelQuery.addEventListener('click', manualLookupThreatIntel);

    const inputSearchIntel = document.getElementById('input-search-intel-cache');
    if (inputSearchIntel) {
        inputSearchIntel.addEventListener('input', () => fetchThreatIntelCache());
    }
    const selectFilterIntelRisk = document.getElementById('select-filter-intel-risk');
    if (selectFilterIntelRisk) {
        selectFilterIntelRisk.addEventListener('change', () => fetchThreatIntelCache());
    }
    const btnRefreshIntelCache = document.getElementById('btn-refresh-intel-cache');
    if (btnRefreshIntelCache) {
        btnRefreshIntelCache.addEventListener('click', () => {
            executeRefreshWithFeedback(
                btnRefreshIntelCache,
                () => fetchThreatIntelCache(),
                '情資清單已更新',
                '已重新載入本地資料庫中的外部 IP 威脅情資紀錄。'
            );
        });
    }

    // Excel Template / Export / Import bindings for Unified Scenario Rules
    const btnDownloadScTemplate = document.getElementById('btn-download-scenario-template');
    if (btnDownloadScTemplate) {
        btnDownloadScTemplate.addEventListener('click', () => {
            window.open('/api/scenarios/template-excel', '_blank');
            showToast('正在下載「智慧情資規則匯入範本.xlsx」...', 'info', '下載範本 EXCEL');
        });
    }
    const btnExportScenarios = document.getElementById('btn-export-scenarios');
    if (btnExportScenarios) {
        btnExportScenarios.addEventListener('click', () => {
            window.open('/api/scenarios/export-excel', '_blank');
            showToast('正在匯出目前所有智慧情資規則至 Excel...', 'info', '匯出規則 EXCEL');
        });
    }
    const btnImportScenarios = document.getElementById('btn-import-scenarios');
    const inputImportScenarios = document.getElementById('input-import-scenarios');
    if (btnImportScenarios && inputImportScenarios) {
        btnImportScenarios.addEventListener('click', () => inputImportScenarios.click());
        inputImportScenarios.addEventListener('change', (e) => {
            const file = e.target.files?.[0];
            if (file) {
                importScenariosFromExcelFile(file);
                inputImportScenarios.value = '';
            }
        });
    }

    // Batch import from Threat Intel DB to Unified Scenario Rules
    const btnBatchImportIntel = document.getElementById('btn-batch-import-intel-to-scenarios');
    if (btnBatchImportIntel) {
        btnBatchImportIntel.addEventListener('click', () => batchImportSelectedIntelToScenarios());
    }
    const chkSelectAllIntel = document.getElementById('chk-select-all-intel');
    if (chkSelectAllIntel) {
        chkSelectAllIntel.addEventListener('change', () => {
            document.querySelectorAll('.chk-intel-item').forEach(chk => {
                chk.checked = chkSelectAllIntel.checked;
            });
        });
    }

    // Drill-down details modal controls
    const btnCloseDrillModal = document.getElementById('btn-close-drill-modal');
    if (btnCloseDrillModal) btnCloseDrillModal.addEventListener('click', closeDrillDetailsModal);
    const drillModal = document.getElementById('modal-drill-details');
    if (drillModal) {
        drillModal.addEventListener('click', (e) => {
            if (e.target === drillModal) closeDrillDetailsModal();
        });
    }
    const btnToggleSankey = document.getElementById('btn-toggle-drill-sankey');
    if (btnToggleSankey) {
        btnToggleSankey.addEventListener('click', () => {
            const body = document.getElementById('drill-sankey-body');
            if (!body) return;
            const isHidden = body.style.display === 'none';
            body.style.display = isHidden ? 'block' : 'none';
            btnToggleSankey.innerHTML = isHidden
                ? '<i data-lucide="chevron-up" style="width: 13px; height: 13px;"></i><span>收合圖表</span>'
                : '<i data-lucide="chevron-down" style="width: 13px; height: 13px;"></i><span>展開圖表</span>';
            if (window.lucide) window.lucide.createIcons();
        });
    }
    const drillChartModeSelect = document.getElementById('drill-chart-mode-select');
    if (drillChartModeSelect) {
        drillChartModeSelect.addEventListener('change', () => {
            const body = document.getElementById('drill-sankey-body');
            if (body && body.style.display === 'none') {
                body.style.display = 'block';
                if (btnToggleSankey) {
                    btnToggleSankey.innerHTML = '<i data-lucide="chevron-up" style="width: 13px; height: 13px;"></i><span>收合圖表</span>';
                    if (window.lucide) window.lucide.createIcons();
                }
            }
            renderActiveDrillChart();
        });
    }

    // Load initial threat intel badge count
    fetchThreatIntelCache();
}

function closeDrillDetailsModal() {
    const modal = document.getElementById('modal-drill-details');
    if (modal) modal.classList.remove('active');
    const tooltip = document.getElementById('drill-sankey-tooltip');
    if (tooltip) tooltip.style.display = 'none';
}

function switchAnomaliesMode(mode) {
    diagState.mode = 'smart';
    const smartPanel = document.getElementById('anomalies-smart-panel');
    if (smartPanel) smartPanel.style.display = 'block';
    if (mode === 'legacy') {
        const modal = document.getElementById('modal-drill-details');
        if (modal) modal.classList.add('active');
        fetchAnomalousReport();
    } else {
        fetchSmartDiagnostics();
    }
    if (window.lucide) window.lucide.createIcons();
}

function refreshAnomaliesActiveView() {
    fetchSmartDiagnostics();
}

async function fetchSmartDiagnostics() {
    const params = new URLSearchParams();
    params.set('time_range', diagState.timeRange || 'custom');
    if (diagState.targetDate && (diagState.timeRange === 'custom' || diagState.timeRange === 'today')) {
        params.set('target_date', diagState.targetDate);
        if (diagState.timeRange === 'custom') {
            if (diagState.startTime) params.set('start_time', diagState.startTime);
            if (diagState.endTime) params.set('end_time', diagState.endTime);
        }
    }

    try {
        const signal = getAbortSignal('smartDiagnostics');
        const res = await fetch(`/api/anomalies/diagnostics?${params.toString()}`, { signal });
        if (!res.ok) throw new Error('無法載入智慧情境診斷資料');
        const data = await res.json();

        diagState.events = data.events || [];
        diagState.rawCharts = data.charts || {};
        diagState.summary = data.summary || {};
        if (data.summary.target_date) {
            diagState.targetDate = data.summary.target_date;
        }
        if (data.summary.time_label) {
            diagState.timeLabel = data.summary.time_label;
        }
        if (diagState.severity && (diagState.summary[`${diagState.severity}_count`] || 0) === 0 && (diagState.summary.total_events || 0) > 0) {
            diagState.severity = '';
        }

        updateTier1Cards(diagState.summary);
        updateTierBreadcrumbs();
        renderTier2Charts();
        renderFilteredEquipmentList();

        const nacBadge = document.getElementById('diag-athenac-badge');
        if (nacBadge) {
            if (diagState.summary.athenac_mode === 'live') {
                nacBadge.className = 'badge badge-success';
                nacBadge.innerHTML = '<i data-lucide="cpu" style="width:13px;height:13px;"></i><span>AtheNAC 即時連線</span>';
            } else {
                nacBadge.className = 'badge badge-info';
                nacBadge.innerHTML = '<i data-lucide="cpu" style="width:13px;height:13px;"></i><span>AtheNAC 模擬資訊</span>';
            }
        }

        if (window.lucide) window.lucide.createIcons();
    } catch (err) {
        if (err.name === 'AbortError') return;
        console.error('Diagnostics error:', err);
        const tbody = document.getElementById('diag-events-tbody');
        if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="text-center text-danger py-4">診斷分析失敗: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function updateTier1Cards(s) {
    const setEl = (id, v) => { const e = document.getElementById(id); if (e) e.innerText = v; };
    setEl('diag-kpi-total', formatNumber(s.total_events || 0));
    setEl('diag-kpi-total-sub', `${formatNumber(s.total_hosts || 0)} 台設備`);

    setEl('diag-kpi-high', formatNumber(s.high_count || 0));
    setEl('diag-kpi-high-sub', `${formatNumber(s.high_hosts || 0)} 台設備`);

    setEl('diag-kpi-medium', formatNumber(s.medium_count || 0));
    setEl('diag-kpi-medium-sub', `${formatNumber(s.medium_hosts || 0)} 台設備`);

    setEl('diag-kpi-low', formatNumber(s.low_count || 0));
    setEl('diag-kpi-low-sub', `${formatNumber(s.low_hosts || 0)} 台設備`);

    setEl('diag-kpi-behavior', formatNumber(s.behavior_count || 0));
    setEl('diag-kpi-behavior-sub', `${formatNumber(s.behavior_hosts || 0)} 台設備`);

    document.querySelectorAll('.diag-kpi-card').forEach(card => {
        const sev = card.dataset.severity || '';
        if (sev === diagState.severity) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });
}

function updateTierBreadcrumbs() {
    const wrapper = document.getElementById('tier-breadcrumb-wrapper');
    if (!wrapper) return;

    const sevLabels = {
        '': '全部等級',
        'high': '🔴 高風險',
        'medium': '🟠 中風險',
        'low': '🟡 低風險',
        'behavior': '🔵 行為管理'
    };

    const crumbs = [];

    // Crumb 1: Root / All (with selected date)
    const dateLabel = (diagState.timeRange === 'custom' || diagState.timeRange === 'today') && diagState.targetDate
        ? ` (${diagState.targetDate})`
        : (diagState.timeRange === '24h' ? ' (近24H)' : (diagState.timeRange === '7d' ? ' (近7天)' : ''));
    crumbs.push(`<span class="tier-crumb ${diagState.severity === '' ? 'active' : ''}" onclick="selectTier1Severity('')">總覽${dateLabel}</span>`);

    // Crumb 2: Current Severity
    if (diagState.severity) {
        crumbs.push(`<span class="tier-crumb-arrow">❯</span>`);
        crumbs.push(`<span class="tier-crumb ${!diagState.scenarioId ? 'active' : ''}" onclick="selectTier1Severity('${diagState.severity}')">${sevLabels[diagState.severity] || diagState.severity}</span>`);
    }

    // Crumb 3: Scenario if selected
    if (diagState.scenarioId) {
        crumbs.push(`<span class="tier-crumb-arrow">❯</span>`);
        crumbs.push(`<span class="tier-crumb active" onclick="clearTier2Scenario()">情境: ${escapeHtml(diagState.scenarioName)} <i data-lucide="x" style="width:12px;height:12px;margin-left:3px;vertical-align:middle;"></i></span>`);
    }

    wrapper.innerHTML = crumbs.join('');

    // Update Tier 2 header and tags
    const activeSevName = sevLabels[diagState.severity] || '全部等級';
    const t2Title = document.getElementById('tier2-section-title');
    if (t2Title) t2Title.innerText = `各類型風險情境視覺分析（目前層級：${activeSevName}）`;

    const tagWrapper = document.getElementById('tier2-active-scenario-tag');
    const tagName = document.getElementById('tier2-active-scenario-name');
    if (tagWrapper && tagName) {
        if (diagState.scenarioId) {
            tagWrapper.style.display = 'inline-flex';
            tagName.innerText = `已鎖定情境：${diagState.scenarioName}`;
        } else {
            tagWrapper.style.display = 'none';
        }
    }

    // Active filter bar in Tier 3
    const filterBar = document.getElementById('diag-active-filter-bar');
    const filterLabel = document.getElementById('diag-active-filter-label');
    const activeFilters = [];
    if (diagState.severity) activeFilters.push(`等級=${sevLabels[diagState.severity]}`);
    if (diagState.scenarioName) activeFilters.push(`情境=${diagState.scenarioName}`);
    if (diagState.hostIp) activeFilters.push(`主機=${diagState.hostIp}`);

    if (filterBar && filterLabel) {
        if (activeFilters.length > 0) {
            filterBar.style.display = 'flex';
            filterLabel.innerText = `已篩選: ${activeFilters.join(' | ')}`;
        } else {
            filterBar.style.display = 'none';
        }
    }
}

function selectTier1Severity(sev) {
    diagState.severity = sev;
    diagState.scenarioId = null;
    diagState.scenarioName = '';
    diagState.category = '';
    diagState.hostIp = '';
    updateTier1Cards(diagState.summary);
    updateTierBreadcrumbs();
    renderTier2Charts();
    renderFilteredEquipmentList();
}

function clearTier2Scenario() {
    diagState.scenarioId = null;
    diagState.scenarioName = '';
    updateTierBreadcrumbs();
    renderTier2Charts();
    renderFilteredEquipmentList();
}

function renderTier2Charts() {
    const rawScenarios = diagState.rawCharts.by_scenario || [];
    // Filter scenarios by active Tier 1 severity
    const activeScenarios = diagState.severity
        ? rawScenarios.filter(s => s.severity === diagState.severity)
        : rawScenarios;

    // Professional, cohesive dark cybersecurity palette
    const cyberPalette = [
        '#6366f1', '#e11d48', '#0ea5e9', '#f59e0b', '#10b981',
        '#8b5cf6', '#ec4899', '#14b8a6', '#f97316', '#64748b'
    ];

    // Chart 1: Scenario Doughnut Chart
    destroyChart('chart-diag-categories');
    const ctxSc = document.getElementById('chart-diag-categories');
    if (ctxSc) {
        if (activeScenarios.length === 0) {
            // Render empty placeholder
            state.charts['chart-diag-categories'] = new Chart(ctxSc, {
                type: 'doughnut',
                data: {
                    labels: ['無符合事件'],
                    datasets: [{ data: [1], backgroundColor: ['#374151'], borderWidth: 0 }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false }, tooltip: { enabled: false } }
                }
            });
        } else {
            state.charts['chart-diag-categories'] = new Chart(ctxSc, {
                type: 'doughnut',
                data: {
                    labels: activeScenarios.map(s => s.name),
                    datasets: [{
                        data: activeScenarios.map(s => s.events),
                        backgroundColor: activeScenarios.map((_, i) => cyberPalette[i % cyberPalette.length]),
                        borderColor: '#111827',
                        borderWidth: 2,
                        hoverOffset: 8
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    onClick: (_, elements) => {
                        if (!elements.length) return;
                        const clickedIdx = elements[0].index;
                        const sc = activeScenarios[clickedIdx];
                        if (diagState.scenarioId === sc.scenario_id) {
                            diagState.scenarioId = null;
                            diagState.scenarioName = '';
                        } else {
                            diagState.scenarioId = sc.scenario_id;
                            diagState.scenarioName = sc.name;
                        }
                        updateTierBreadcrumbs();
                        renderFilteredEquipmentList();

                        const tier3 = document.getElementById('tier3-container');
                        if (tier3) {
                            tier3.scrollIntoView({ behavior: 'smooth', block: 'start' });
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: '#d1d5db',
                                font: { size: 11 },
                                boxWidth: 12,
                                padding: 10
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.95)',
                            titleColor: '#f3f4f6',
                            bodyColor: '#e5e7eb',
                            borderColor: 'rgba(99, 102, 241, 0.4)',
                            borderWidth: 1,
                            padding: 12,
                            boxPadding: 6,
                            usePointStyle: true,
                            callbacks: {
                                title: (items) => {
                                    const sc = activeScenarios[items[0].dataIndex];
                                    return `🚨 ${sc.name}`;
                                },
                                label: (item) => {
                                    const sc = activeScenarios[item.dataIndex];
                                    return [
                                        ` 所屬分類: ${sc.category}`,
                                        ` 受波及主機: ${sc.hosts_count} 台內部設備`,
                                        ` 累計連線數: ${formatNumber(sc.flows)} 筆 Flow`,
                                        ` 總傳輸流量: ${formatBytes(sc.bytes)}`,
                                        ` 常見通訊埠: ${sc.ports_summary || '多埠'}`,
                                        ` 👉 點擊色塊切換設備清單`
                                    ];
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    // Chart 2: 24-Hour Hotspot Stacked Bar Chart
    const hourlyTitle = document.getElementById('tier2-chart2-title');
    if (hourlyTitle) {
        if (diagState.targetDate && (diagState.timeRange === 'custom' || diagState.timeRange === 'today')) {
            hourlyTitle.innerText = `${diagState.targetDate} 24 小時異常時段分佈熱區 (堆疊長條)`;
        } else {
            hourlyTitle.innerText = `24 小時異常時段分佈熱區 (堆疊長條)`;
        }
    }
    const hourData = diagState.rawCharts.by_hour || [];
    destroyChart('chart-diag-hourly');
    const ctxHour = document.getElementById('chart-diag-hourly');
    if (ctxHour) {
        state.charts['chart-diag-hourly'] = new Chart(ctxHour, {
            type: 'bar',
            data: {
                labels: hourData.map(x => x.hour.slice(0, 2) + 'h'),
                datasets: [
                    { label: '高', data: hourData.map(x => x.high || 0), backgroundColor: 'rgba(239, 68, 68, 0.85)', borderRadius: 3 },
                    { label: '中', data: hourData.map(x => x.medium || 0), backgroundColor: 'rgba(245, 158, 11, 0.85)', borderRadius: 3 },
                    { label: '低', data: hourData.map(x => x.low || 0), backgroundColor: 'rgba(16, 185, 129, 0.85)', borderRadius: 3 },
                    { label: '行為管理', data: hourData.map(x => x.behavior || 0), backgroundColor: 'rgba(14, 165, 233, 0.85)', borderRadius: 3 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { color: '#d1d5db', font: { size: 10 }, boxWidth: 10, padding: 8 }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        borderColor: 'rgba(255, 255, 255, 0.1)',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        stacked: true,
                        ticks: { color: '#9ca3af', font: { size: 10 } },
                        grid: { color: 'rgba(255,255,255,0.03)' }
                    },
                    y: {
                        stacked: true,
                        ticks: { color: '#9ca3af', precision: 0 },
                        grid: { color: 'rgba(255,255,255,0.05)' }
                    }
                }
            }
        });
    }
}

function getSeverityBadgeHtml(sev) {
    if (sev === 'high') {
        return `<span class="badge" style="background: rgba(239,68,68,0.18); color: #f87171; border: 1px solid rgba(239,68,68,0.4);">🔴 高・立即阻斷</span>`;
    }
    if (sev === 'medium') {
        return `<span class="badge" style="background: rgba(245,158,11,0.18); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4);">🟠 中・清查確認</span>`;
    }
    if (sev === 'low') {
        return `<span class="badge" style="background: rgba(16,185,129,0.18); color: #34d399; border: 1px solid rgba(16,185,129,0.4);">🟡 低・常規關注</span>`;
    }
    return `<span class="badge" style="background: rgba(14,165,233,0.18); color: #38bdf8; border: 1px solid rgba(14,165,233,0.4);">🔵 行為・頻寬管理</span>`;
}

let _filteredEventsList = [];

const TIER3_COL_ORDER_STORAGE_KEY = 'superflow_tier3_col_order_v1';
const TIER3_COL_WIDTH_STORAGE_KEY = 'superflow_tier3_col_widths_v1';

const TIER3_COLUMNS_META = {
    host:     { key: 'host',     label: 'IP',                         defaultPct: '13%', minPx: 105, align: 'left' },
    athenac:  { key: 'athenac',  label: 'AtheNAC 資產識別',           defaultPct: '14%', minPx: 110, align: 'left' },
    location: { key: 'location', label: '實體網路位置 (Switch/Port)', defaultPct: '14%', minPx: 115, align: 'left' },
    severity: { key: 'severity', label: '風險等級',                   defaultPct: '10%', minPx: 95,  align: 'center' },
    status:   { key: 'status',   label: '處理狀態',                   defaultPct: '11%', minPx: 100, align: 'center' },
    scenario: { key: 'scenario', label: '風險名稱',                   defaultPct: '15%', minPx: 120, align: 'left' },
    scale:    { key: 'scale',    label: '異常規模 / 最後時間',         defaultPct: '11%', minPx: 105, align: 'right' },
    actions:  { key: 'actions',  label: '處置操作',                   defaultPct: '11%', minPx: 115, align: 'center' }
};
const TIER3_DEFAULT_COL_ORDER = ['host', 'athenac', 'location', 'severity', 'status', 'scenario', 'scale', 'actions'];

function getTier3ColOrder() {
    try {
        const raw = localStorage.getItem(TIER3_COL_ORDER_STORAGE_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed) && parsed.length === TIER3_DEFAULT_COL_ORDER.length &&
                TIER3_DEFAULT_COL_ORDER.every(k => parsed.includes(k))) {
                return parsed;
            }
        }
    } catch (e) {}
    return [...TIER3_DEFAULT_COL_ORDER];
}

function getTier3ColWidths() {
    try {
        const raw = localStorage.getItem(TIER3_COL_WIDTH_STORAGE_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object') return parsed;
        }
    } catch (e) {}
    return {};
}

function saveTier3ColOrder(order) {
    try {
        localStorage.setItem(TIER3_COL_ORDER_STORAGE_KEY, JSON.stringify(order));
    } catch (e) {}
}

function saveTier3ColWidths(widths) {
    try {
        localStorage.setItem(TIER3_COL_WIDTH_STORAGE_KEY, JSON.stringify(widths));
    } catch (e) {}
}

function resetTier3Columns() {
    try {
        localStorage.removeItem(TIER3_COL_ORDER_STORAGE_KEY);
        localStorage.removeItem(TIER3_COL_WIDTH_STORAGE_KEY);
    } catch (e) {}
    const tableEl = document.getElementById('diag-events-table');
    if (tableEl) tableEl.style.width = '100%';
    renderTier3TableHeader();
    renderFilteredEquipmentList();
    showToast('已還原欄位預設順序與寬度', 'info', '欄位已重設');
}

let _tier3DraggedColKey = null;

function renderTier3TableHeader() {
    const theadTr = document.getElementById('diag-events-thead-tr');
    const colgroup = document.getElementById('diag-events-colgroup');
    if (!theadTr) return;

    const order = getTier3ColOrder();
    const widths = getTier3ColWidths();

    if (colgroup) {
        colgroup.innerHTML = order.map(k => {
            const meta = TIER3_COLUMNS_META[k];
            const w = widths[k] ? `${widths[k]}px` : meta.defaultPct;
            return `<col data-col-key="${k}" style="width: ${w};">`;
        }).join('');
    }

    theadTr.innerHTML = order.map(k => {
        const meta = TIER3_COLUMNS_META[k];
        const w = widths[k] ? `${widths[k]}px` : meta.defaultPct;
        const pad = (meta.align === 'center') ? '12px 10px' : '12px 12px';
        return `
            <th class="tier3-th" draggable="true" data-col-key="${k}" title="拖曳標題可調整欄位順序；拖拉右側邊線可調整欄寬" style="width: ${w}; padding: ${pad}; text-align: ${meta.align}; font-weight: 600; color: var(--text-muted); background: #1f2937;">
                <span class="tier3-th-inner">
                    <span class="tier3-grip">⋮⋮</span>
                    <span>${escapeHtml(meta.label)}</span>
                </span>
                <div class="tier3-col-resizer" data-resize-key="${k}" title="左右拖拉調整欄寬"></div>
            </th>
        `;
    }).join('');

    // Bind column drag-and-drop reordering
    theadTr.querySelectorAll('th.tier3-th').forEach(th => {
        th.addEventListener('dragstart', (e) => {
            if (th.getAttribute('data-resizing') === '1') {
                e.preventDefault();
                return;
            }
            _tier3DraggedColKey = th.getAttribute('data-col-key');
            th.classList.add('dragging');
            if (e.dataTransfer) {
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', _tier3DraggedColKey);
            }
        });

        th.addEventListener('dragend', () => {
            th.classList.remove('dragging');
            theadTr.querySelectorAll('th.tier3-th').forEach(el => el.classList.remove('drag-over'));
            _tier3DraggedColKey = null;
        });

        th.addEventListener('dragover', (e) => {
            e.preventDefault();
            if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
            const targetKey = th.getAttribute('data-col-key');
            if (_tier3DraggedColKey && targetKey !== _tier3DraggedColKey) {
                th.classList.add('drag-over');
            }
        });

        th.addEventListener('dragleave', () => {
            th.classList.remove('drag-over');
        });

        th.addEventListener('drop', (e) => {
            e.preventDefault();
            th.classList.remove('drag-over');
            const targetKey = th.getAttribute('data-col-key');
            const srcKey = _tier3DraggedColKey || (e.dataTransfer ? e.dataTransfer.getData('text/plain') : null);
            if (!srcKey || !targetKey || srcKey === targetKey) return;

            const curOrder = getTier3ColOrder();
            const fromIdx = curOrder.indexOf(srcKey);
            const toIdx = curOrder.indexOf(targetKey);
            if (fromIdx === -1 || toIdx === -1) return;

            curOrder.splice(fromIdx, 1);
            curOrder.splice(toIdx, 0, srcKey);
            saveTier3ColOrder(curOrder);
            renderTier3TableHeader();
            renderFilteredEquipmentList();
        });
    });

    // Bind column width resizers
    theadTr.querySelectorAll('.tier3-col-resizer').forEach(handle => {
        handle.addEventListener('mousedown', (e) => {
            e.stopPropagation();
            e.preventDefault();
            const colKey = handle.getAttribute('data-resize-key');
            const th = handle.closest('th.tier3-th');
            if (!th || !colKey) return;

            th.setAttribute('data-resizing', '1');
            th.draggable = false;
            handle.classList.add('resizing');

            // Snapshot all current column pixel widths so resizing one column doesn't jump others
            const curWidths = getTier3ColWidths();
            theadTr.querySelectorAll('th.tier3-th').forEach(hEl => {
                const k = hEl.getAttribute('data-col-key');
                const wPx = Math.round(hEl.getBoundingClientRect().width);
                curWidths[k] = wPx;
                hEl.style.width = `${wPx}px`;
                const cEl = colgroup ? colgroup.querySelector(`col[data-col-key="${k}"]`) : null;
                if (cEl) cEl.style.width = `${wPx}px`;
            });

            const startX = e.clientX;
            const startWidth = curWidths[colKey] || Math.round(th.getBoundingClientRect().width);
            const minWidth = (TIER3_COLUMNS_META[colKey] && TIER3_COLUMNS_META[colKey].minPx) || 80;
            const colEl = colgroup ? colgroup.querySelector(`col[data-col-key="${colKey}"]`) : null;

            const onMouseMove = (moveEv) => {
                const delta = moveEv.clientX - startX;
                const newW = Math.max(minWidth, startWidth + delta);
                curWidths[colKey] = newW;
                th.style.width = `${newW}px`;
                if (colEl) colEl.style.width = `${newW}px`;
            };

            const onMouseUp = () => {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                handle.classList.remove('resizing');
                th.removeAttribute('data-resizing');
                th.draggable = true;
                saveTier3ColWidths(curWidths);
            };

            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    });
}

function renderFilteredEquipmentList() {
    const tbody = document.getElementById('diag-events-tbody');
    if (!tbody) return;
    const theadTr = document.getElementById('diag-events-thead-tr');
    if (theadTr && !theadTr.querySelector('.tier3-col-resizer')) {
        renderTier3TableHeader();
    }
    const colOrder = getTier3ColOrder();

    // Filter events by severity, scenarioId, hostIp, and incidentStatus
    let filtered = diagState.events || [];
    if (diagState.severity) {
        filtered = filtered.filter(ev => ev.severity === diagState.severity);
    }
    if (diagState.scenarioId) {
        filtered = filtered.filter(ev => ev.scenario_id === diagState.scenarioId);
    }
    if (diagState.hostIp) {
        filtered = filtered.filter(ev => ev.host_ip === diagState.hostIp);
    }
    if (diagState.incidentStatus) {
        filtered = filtered.filter(ev => (ev.incident_status || 'open') === diagState.incidentStatus);
    }

    _filteredEventsList = filtered;

    // Update Tier 3 Table Title
    const titleEl = document.getElementById('tier3-table-title');
    if (titleEl) {
        titleEl.innerHTML = `<i data-lucide="server" style="color: #34d399; width: 19px; height: 19px;"></i><span>異常設備清單（共 ${filtered.length} 台受影響設備）</span>`;
    }

    if (!filtered || filtered.length === 0) {
        const dText = (diagState.timeRange === 'custom' || diagState.timeRange === 'today') && diagState.targetDate
            ? `指定日期 ${diagState.targetDate}`
            : (diagState.timeLabel || '當前時間週期');
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-5" style="padding: 40px 0;">所選條件與【${escapeHtml(dText)}】下無任何情境異常設備。</td></tr>`;
        if (window.lucide) window.lucide.createIcons();
        return;
    }

    tbody.innerHTML = filtered.map((ev, idx) => {
        const nac = ev.athenac || {};
        const contact = ev.asset_contact || {};
        const hostTitle = ev.host_alias ? `${escapeHtml(ev.host_alias)}` : (nac.hostname ? escapeHtml(nac.hostname) : escapeHtml(ev.host_ip));
        const nacHostName = nac.hostname ? escapeHtml(nac.hostname) : '<span class="text-muted">未登記名稱</span>';
        const nacMac = nac.mac ? `<code>${escapeHtml(nac.mac)}</code>` : '<span class="text-muted">無 MAC 紀錄</span>';
        const nacVendorOs = [nac.vendor, nac.os_detail].filter(Boolean).map(escapeHtml).join(' / ') || '<span class="text-muted">一般網路設備</span>';

        const switchPort = (nac.switch_name || nac.port_name)
            ? `${escapeHtml((nac.switch_name + ' ' + nac.port_name).trim())}`
            : '<span class="text-muted">未納管或無交換機資料</span>';

        const onlineDot = nac.is_online
            ? '<span style="color:#34d399; font-size:0.75rem; margin-right:4px;">●</span>'
            : '<span style="color:#9ca3af; font-size:0.75rem; margin-right:4px;">○</span>';

        const ownerChipParts = [];
        if (contact.owner_name) ownerChipParts.push(`👤 ${escapeHtml(contact.owner_name)}${contact.department ? ` (${escapeHtml(contact.department)})` : ''}`);
        if (contact.vendor_name) ownerChipParts.push(`🏢 ${escapeHtml(contact.vendor_name)}`);
        const ownerChipHtml = ownerChipParts.length > 0
            ? `<div style="margin-top: 5px; font-size: 0.72rem; color: #fde68a; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 5px; padding: 2px 6px; display: inline-block; line-height: 1.4;">${ownerChipParts.join(' · ')}</div>`
            : '';

        const statusBadgeHtml = getIncidentStatusBadgeHtml(ev.incident_status || 'open');
        const latestNoteHtml = ev.incident_latest_note
            ? `<div style="margin-top: 5px; padding: 3px 6px; border-radius: 5px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.28); font-size: 0.71rem; color: #a7f3d0; line-height: 1.35; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: left;" title="${escapeHtml(ev.incident_latest_note)}">📝 ${escapeHtml(ev.incident_latest_note)}</div>`
            : '';

        const highRiskIntelCount = (ev.threat_intel || []).filter(ti =>
            ['high', 'critical'].includes((ti.risk_level || '').toLowerCase()) || ti.vulns || ti.risky_ports
        ).length;
        const highRiskChipHtml = highRiskIntelCount > 0
            ? `<div style="margin-top: 5px;"><span class="badge" style="background: rgba(239, 68, 68, 0.16); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); font-size: 0.7rem; padding: 2px 6px; border-radius: 5px;">⚠️ 含高危情資 (${highRiskIntelCount})</span></div>`
            : '';

        const cellsMap = {
            host: `
                <td data-col-key="host" style="padding: 12px 12px; vertical-align: top;">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="font-family: var(--font-mono); font-size: 0.86rem; font-weight: 600; color: var(--text-primary);">${escapeHtml(ev.host_ip)}</span>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="copyTextToClipboard('${escapeHtml(ev.host_ip)}')" style="padding: 2px 5px; font-size: 0.7rem; border-radius: 4px;" title="複製 IP">
                            <i data-lucide="copy" style="width: 11px; height: 11px;"></i>
                        </button>
                    </div>
                    ${ownerChipHtml}
                </td>`,
            athenac: `
                <td data-col-key="athenac" style="padding: 12px 12px; vertical-align: top;">
                    <div style="font-weight: 600; color: var(--text-primary); font-size: 0.84rem; margin-bottom: 2px; word-break: break-word;">${nacHostName}</div>
                    <div style="font-size: 0.75rem; color: var(--text-secondary); margin-bottom: 2px;">${nacMac}</div>
                    <div style="font-size: 0.71rem; color: var(--text-muted); word-break: break-word;">${nacVendorOs}</div>
                </td>`,
            location: `
                <td data-col-key="location" style="padding: 12px 12px; vertical-align: top;">
                    <div style="font-size: 0.82rem; color: var(--text-primary); font-weight: 500; display: flex; align-items: flex-start; gap: 2px; word-break: break-word;">
                        ${onlineDot}<span>${switchPort}</span>
                    </div>
                    <div style="font-size: 0.71rem; color: var(--text-muted); margin-top: 3px;">
                        ${nac.site_name ? escapeHtml(nac.site_name) + ' / ' : ''}${nac.network_name ? escapeHtml(nac.network_name) : ''}
                    </div>
                </td>`,
            severity: `
                <td data-col-key="severity" style="padding: 12px 10px; vertical-align: top; text-align: center;">
                    ${getSeverityBadgeHtml(ev.severity)}
                </td>`,
            status: `
                <td data-col-key="status" style="padding: 12px 10px; vertical-align: top; text-align: center;">
                    <div>${statusBadgeHtml}</div>
                    ${latestNoteHtml}
                </td>`,
            scenario: `
                <td data-col-key="scenario" style="padding: 12px 12px; vertical-align: top;">
                    <div style="font-weight: 600; color: var(--text-primary); font-size: 0.85rem; line-height: 1.4; word-break: break-word;">${escapeHtml(ev.scenario_name)}</div>
                    <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 3px;">${escapeHtml(ev.category)}・${escapeHtml(ev.time_window_label)}</div>
                    ${highRiskChipHtml}
                </td>`,
            scale: `
                <td data-col-key="scale" class="diag-col-nowrap" style="padding: 12px 12px; vertical-align: top; text-align: right; font-family: var(--font-mono);">
                    <div style="font-weight: 700; color: var(--text-primary); font-size: 0.88rem;">${formatBytes(ev.total_bytes)}</div>
                    <div style="font-size: 0.76rem; color: var(--text-secondary); margin-top: 2px;">${formatNumber(ev.flow_count)} 筆連線</div>
                    <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 4px;">${escapeHtml(ev.last_ts)}</div>
                </td>`,
            actions: `
                <td data-col-key="actions" style="padding: 12px 10px; vertical-align: top; text-align: center;">
                    <div style="display: flex; flex-direction: column; gap: 6px; align-items: center;">
                        <button type="button" class="btn btn-primary btn-sm" onclick="openPlaybookModal(${idx})" style="width: 118px; padding: 6px 8px; font-size: 0.78rem; border-radius: 6px; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 5px;">
                            <i data-lucide="book-open" style="width: 13px; height: 13px;"></i>
                            <span>詳細內容</span>
                        </button>
                        <button type="button" class="btn btn-secondary btn-sm" onclick="drillToLegacyAnomalies(${idx})" style="width: 118px; padding: 5px 8px; font-size: 0.74rem; border-radius: 6px; display: flex; align-items: center; justify-content: center; gap: 5px;">
                            <i data-lucide="search" style="width: 12px; height: 12px;"></i>
                            <span>查看底層明細</span>
                        </button>
                    </div>
                </td>`
        };

        return `
            <tr class="flow-row" style="cursor: default;">
                ${colOrder.map(k => cellsMap[k] || '').join('')}
            </tr>
        `;
    }).join('');

    if (window.lucide) window.lucide.createIcons();
}

function getIncidentStatusMeta(status) {
    const st = (status || 'open').toLowerCase();
    if (st === 'vendor_pending') {
        return { label: '🟠 詢問廠商中', bg: 'rgba(245, 158, 11, 0.18)', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.45)' };
    }
    if (st === 'resolved') {
        return { label: '🟢 已解決', bg: 'rgba(16, 185, 129, 0.18)', color: '#34d399', border: 'rgba(16, 185, 129, 0.45)' };
    }
    if (st === 'ignored') {
        return { label: '⚪ 忽略', bg: 'rgba(148, 163, 184, 0.16)', color: '#cbd5e1', border: 'rgba(148, 163, 184, 0.38)' };
    }
    return { label: '🔴 待處理', bg: 'rgba(239, 68, 68, 0.16)', color: '#fca5a5', border: 'rgba(239, 68, 68, 0.4)' };
}

function getIncidentStatusBadgeHtml(status) {
    const m = getIncidentStatusMeta(status);
    return `<span class="badge" style="background:${m.bg}; color:${m.color}; border:1px solid ${m.border}; font-size:0.72rem; padding:2px 7px; border-radius:5px;">${m.label}</span>`;
}

let _currentPlaybookIdx = -1;

function _renderPlaybookContactSummary(ev) {
    const nac = ev.athenac || {};
    const c = ev.asset_contact || {};
    const hostDisplay = document.getElementById('playbook-host-display');
    const locDisplay = document.getElementById('playbook-quick-location');
    const ownerDisplay = document.getElementById('playbook-quick-owner');
    const vendorDisplay = document.getElementById('playbook-quick-vendor');

    const aliasText = c.name || ev.host_alias || nac.hostname || '';
    if (hostDisplay) {
        hostDisplay.innerHTML = `${escapeHtml(ev.host_ip)}${aliasText && aliasText !== ev.host_ip ? `<div style="font-size:0.76rem;color:#a5b4fc;font-family:var(--font-sans);font-weight:500;">${escapeHtml(aliasText)}${c.device_role ? ` · ${escapeHtml(c.device_role)}` : ''}</div>` : (c.device_role ? `<div style="font-size:0.76rem;color:#a5b4fc;font-family:var(--font-sans);font-weight:500;">${escapeHtml(c.device_role)}</div>` : '')}`;
    }
    if (locDisplay) {
        const sw = [nac.switch_name, nac.port_name].filter(Boolean).join(' / ');
        locDisplay.innerText = sw || '未納管 / 無交換機資料';
    }
    if (ownerDisplay) {
        const oParts = [c.owner_name, c.department].filter(Boolean);
        ownerDisplay.innerHTML = oParts.length > 0
            ? escapeHtml(oParts.join(' · '))
            : '<span style="color:var(--text-muted);font-weight:400;">尚未登記（點右上角編輯）</span>';
    }
    if (vendorDisplay) {
        const vParts = [c.vendor_name, c.contact_info].filter(Boolean);
        vendorDisplay.innerHTML = vParts.length > 0
            ? escapeHtml(vParts.join(' · '))
            : '<span style="color:var(--text-muted);font-weight:400;">尚未登記（點右上角編輯）</span>';
    }

    // Pre-fill edit form fields
    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
    setVal('playbook-edit-alias', c.name || ev.host_alias || nac.hostname || '');
    setVal('playbook-edit-owner', c.owner_name || '');
    setVal('playbook-edit-dept', c.department || '');
    setVal('playbook-edit-vendor', c.vendor_name || '');
    setVal('playbook-edit-contact', c.contact_info || '');
    setVal('playbook-edit-role', c.device_role || '');
}

function _renderPlaybookStatusBadge(status) {
    const badge = document.getElementById('playbook-incident-status-badge');
    const sel = document.getElementById('playbook-incident-status-select');
    const m = getIncidentStatusMeta(status);
    if (badge) {
        badge.innerText = m.label;
        badge.style.background = m.bg;
        badge.style.color = m.color;
        badge.style.border = `1px solid ${m.border}`;
    }
    if (sel) sel.value = status || 'open';
}

function _renderPlaybookNotesTimeline(notes) {
    const el = document.getElementById('playbook-notes-timeline');
    if (!el) return;
    if (!notes || notes.length === 0) {
        el.innerHTML = `<div style="font-size: 0.8rem; color: var(--text-muted); text-align: center; padding: 8px 0;">尚無廠商回覆或處置備註紀錄</div>`;
        return;
    }
    el.innerHTML = notes.map(n => `
        <div style="background: rgba(0, 0, 0, 0.28); border: 1px solid rgba(255,255,255,0.08); border-radius: 7px; padding: 8px 11px;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px; flex-wrap: wrap;">
                <div style="display: flex; align-items: center; gap: 6px;">
                    ${getIncidentStatusBadgeHtml(n.status)}
                    <span style="font-size: 0.74rem; color: #94a3b8;">${escapeHtml(n.author || 'admin')}</span>
                </div>
                <span style="font-size: 0.72rem; font-family: var(--font-mono); color: var(--text-muted);">${escapeHtml(n.created_at || '')}</span>
            </div>
            <div style="font-size: 0.84rem; color: #f1f5f9; line-height: 1.5; white-space: pre-wrap;">${escapeHtml(n.note || '')}</div>
        </div>
    `).join('');
}

function openPlaybookModal(idx) {
    const ev = _filteredEventsList[idx] || diagState.events[idx];
    if (!ev) return;
    _currentPlaybookIdx = idx;

    const modal = document.getElementById('modal-diagnostic-playbook');
    const banner = document.getElementById('playbook-severity-banner');
    const sevBadge = document.getElementById('playbook-severity-badge');

    document.getElementById('playbook-category-label').innerText = `${ev.category} ・ ${ev.time_window_label}`;
    document.getElementById('playbook-scenario-name').innerText = ev.scenario_name;

    if (ev.severity === 'high') {
        banner.style.background = 'rgba(239, 68, 68, 0.14)';
        banner.style.border = '1px solid rgba(239, 68, 68, 0.35)';
        sevBadge.innerText = '🔴 高・需立即阻斷';
        sevBadge.className = 'badge badge-danger';
    } else if (ev.severity === 'medium') {
        banner.style.background = 'rgba(245, 158, 11, 0.14)';
        banner.style.border = '1px solid rgba(245, 158, 11, 0.35)';
        sevBadge.innerText = '🟠 中・需清查確認';
        sevBadge.className = 'badge badge-warning';
    } else if (ev.severity === 'low') {
        banner.style.background = 'rgba(16, 185, 129, 0.14)';
        banner.style.border = '1px solid rgba(16, 185, 129, 0.35)';
        sevBadge.innerText = '🟡 低・常規關注';
        sevBadge.className = 'badge badge-success';
    } else {
        banner.style.background = 'rgba(14, 165, 233, 0.14)';
        banner.style.border = '1px solid rgba(14, 165, 233, 0.35)';
        sevBadge.innerText = '🔵 行為管理・頻寬合規';
        sevBadge.className = 'badge badge-info';
    }

    const nac = ev.athenac || {};
    const swPort = [nac.switch_name, nac.port_name].filter(Boolean).join(' / ');
    const targetsStr = (ev.targets || []).map(t => t.alias ? `${t.alias} (${t.ip})` : t.ip).join('、') || '外部網路';
    const portsStr = (ev.ports || []).map(p => p.name ? `${p.port} (${p.name})` : p.port).join('、') || '多種連接埠';

    // Build ultra-concise 1-line summary (no duplicate IP, no wall of target text)
    const hostAliasOnly = (ev.host_alias && ev.host_alias !== ev.host_ip) ? ev.host_alias : (nac.hostname && nac.hostname !== ev.host_ip ? nac.hostname : '');
    const hostDisplayInline = hostAliasOnly
        ? `<strong>${escapeHtml(hostAliasOnly)}</strong> (<code style="font-family:var(--font-mono);">${escapeHtml(ev.host_ip)}</code>)`
        : `<strong style="font-family:var(--font-mono);">${escapeHtml(ev.host_ip)}</strong>`;
    const tiList = ev.threat_intel || [];
    const highRiskTi = tiList.filter(t => ['high', 'critical'].includes((t.risk_level || '').toLowerCase()) || t.vulns || t.risky_ports);
    const targetCount = (ev.targets || []).length;
    const targetShort = targetCount === 1
        ? escapeHtml(targetsStr)
        : `${targetCount} 個目標`;

    const onelineEl = document.getElementById('playbook-oneline-summary');
    if (onelineEl) {
        const locBadge = swPort ? `<span style="color:#38bdf8;font-family:var(--font-mono);">[${escapeHtml(swPort)}]</span> ` : '';
        const riskTail = highRiskTi.length > 0
            ? ` · <span style="color:#fca5a5;font-weight:700;">⚠️ 偵測到 ${highRiskTi.length} 筆高危情資 / CVE 弱點</span>`
            : '';
        onelineEl.innerHTML = `${locBadge}${hostDisplayInline} ➔ 存取 <strong>${targetShort}</strong>（Port ${escapeHtml(portsStr)}）· 累計 <strong>${formatBytes(ev.total_bytes)}</strong> / <strong>${formatNumber(ev.flow_count)} 筆連線</strong>${riskTail}`;
    }

    // Update collapsible badges
    const targetsCountBadge = document.getElementById('playbook-targets-count-badge');
    if (targetsCountBadge) {
        targetsCountBadge.innerText = `${targetCount} 個目標${tiList.length > 0 ? ` · ${tiList.length} 筆情資` : ''}`;
    }
    const highRiskBadge = document.getElementById('playbook-highrisk-alert-badge');
    if (highRiskBadge) {
        if (highRiskTi.length > 0) {
            highRiskBadge.style.display = 'inline-flex';
            highRiskBadge.innerText = `⚠️ 含 ${highRiskTi.length} 筆高危 / CVE 弱點`;
        } else {
            highRiskBadge.style.display = 'none';
        }
    }

    // Section 1: Contact summary & status
    _renderPlaybookContactSummary(ev);
    _renderPlaybookStatusBadge(ev.incident_status || 'open');
    const editBox = document.getElementById('playbook-contact-edit-box');
    if (editBox) editBox.style.display = 'none';

    // Section 2: Behavior & Threat evidence
    document.getElementById('playbook-target-display').innerText = `${targetsStr}\n[Port: ${portsStr}]`;
    const scaleEl = document.getElementById('playbook-scale-display');
    if (scaleEl) {
        scaleEl.innerText = `累計流量：${formatBytes(ev.total_bytes)} · 共 ${formatNumber(ev.flow_count)} 筆連線\n最後活動時間：${ev.last_ts || '-'}`;
    }

    const threatBox = document.getElementById('playbook-threat-evidence-box');
    if (threatBox) {
        if (tiList.length > 0) {
            threatBox.style.display = 'block';
            threatBox.innerHTML = `<div style="font-weight:700;color:#fca5a5;margin-bottom:5px;">🛡️ 威脅情資與漏洞偵測證據：</div>` + tiList.map(ti => {
                const vulnPart = ti.vulns ? ` ｜ <span style="color:#f87171;font-weight:700;">弱點/CVE：${escapeHtml(ti.vulns)}</span>` : '';
                const portPart = ti.risky_ports ? ` ｜ 風險埠：<code>${escapeHtml(ti.risky_ports)}</code>` : '';
                return `<div style="margin-bottom:3px;">• <strong style="font-family:var(--font-mono);">${escapeHtml(ti.ip)}</strong>${ti.domain ? ` (${escapeHtml(ti.domain)})` : ''} — 風險分數 <strong>${ti.risk_score}</strong> (${escapeHtml(ti.risk_level || '')})${portPart}${vulnPart} <span style="opacity:0.75;">[${escapeHtml(ti.provider || 'DB')}]</span></div>`;
            }).join('');
        } else {
            threatBox.style.display = 'none';
            threatBox.innerHTML = '';
        }
    }

    document.getElementById('playbook-reason-text').innerText = ev.reason_text;
    document.getElementById('playbook-anomaly-point').innerText = ev.anomaly_point;

    // Section 4: Collapsible AtheNAC & SOP (collapsed by default)
    document.getElementById('playbook-athenac-mode').innerText = nac.is_simulated ? '模擬設備資訊' : 'PIXIS 即時同步';
    document.getElementById('playbook-nac-hostname').innerText = nac.hostname || '無資料';
    document.getElementById('playbook-nac-mac').innerText = nac.mac || '無資料';
    document.getElementById('playbook-nac-location').innerText = swPort || '無資料';
    document.getElementById('playbook-nac-vendor-os').innerText = [nac.vendor, nac.os_detail].filter(Boolean).join(' / ') || '無資料';
    document.getElementById('playbook-nac-network').innerText = [nac.site_name, nac.network_name].filter(Boolean).join(' / ') || '無資料';
    document.getElementById('playbook-nac-online').innerHTML = nac.is_online
        ? '<span style="color:#34d399;font-weight:600;">● 線上 (Online)</span>'
        : '<span style="color:#9ca3af;">○ 離線 / 外部</span>';

    const stepsList = document.getElementById('playbook-steps-list');
    stepsList.innerHTML = (ev.remediation_steps || []).map(s => `<li>${escapeHtml(s.replace(/^\d+\.\s*/, ''))}</li>`).join('');

    // Reset all 3 collapsible sections to collapsed by default
    const targetsBody = document.getElementById('playbook-targets-body');
    const evidenceBody = document.getElementById('playbook-evidence-body');
    const techBody = document.getElementById('playbook-tech-details-body');
    [
        [targetsBody, 'icon-playbook-targets-chevron-wrap'],
        [evidenceBody, 'icon-playbook-evidence-chevron-wrap'],
        [techBody, 'icon-playbook-tech-chevron-wrap']
    ].forEach(([bodyEl, wrapId]) => {
        if (bodyEl) bodyEl.style.display = 'none';
        const wrap = document.getElementById(wrapId);
        if (wrap) wrap.innerHTML = '<i data-lucide="chevron-down" style="width: 15px; height: 15px; color: var(--text-muted);"></i>';
    });

    // Reset note input and fetch incident notes timeline
    const noteInput = document.getElementById('playbook-note-input');
    if (noteInput) noteInput.value = '';
    const timelineEl = document.getElementById('playbook-notes-timeline');
    if (timelineEl) timelineEl.innerHTML = `<div style="font-size:0.78rem;color:var(--text-muted);text-align:center;padding:4px 0;">正在載入備註紀錄...</div>`;
    fetchIncidentNotesForModal(ev);

    // Wire buttons
    const btnToggleEdit = document.getElementById('btn-toggle-edit-contact');
    if (btnToggleEdit) {
        btnToggleEdit.onclick = () => {
            if (!editBox) return;
            editBox.style.display = (editBox.style.display === 'none') ? 'block' : 'none';
        };
    }
    const btnCancelEdit = document.getElementById('btn-cancel-edit-contact');
    if (btnCancelEdit) {
        btnCancelEdit.onclick = () => { if (editBox) editBox.style.display = 'none'; };
    }
    const btnSaveEdit = document.getElementById('btn-save-edit-contact');
    if (btnSaveEdit) {
        btnSaveEdit.onclick = () => savePlaybookAssetContact(ev);
    }
    const btnCopyVendor = document.getElementById('btn-playbook-copy-vendor');
    if (btnCopyVendor) {
        btnCopyVendor.onclick = () => copyVendorInquiryMessage(ev);
    }
    const btnSaveNote = document.getElementById('btn-save-incident-note');
    if (btnSaveNote) {
        btnSaveNote.onclick = () => saveIncidentNoteFromModal(ev);
    }

    const bindAccordion = (btnId, bodyEl, wrapId) => {
        const btn = document.getElementById(btnId);
        if (!btn || !bodyEl) return;
        btn.onclick = () => {
            const isHidden = window.getComputedStyle(bodyEl).display === 'none';
            bodyEl.style.display = isHidden ? 'block' : 'none';
            const wrap = document.getElementById(wrapId);
            if (wrap) wrap.innerHTML = `<i data-lucide="${isHidden ? 'chevron-up' : 'chevron-down'}" style="width: 15px; height: 15px;"></i>`;
            if (window.lucide) window.lucide.createIcons();
        };
    };
    bindAccordion('btn-toggle-playbook-targets', targetsBody, 'icon-playbook-targets-chevron-wrap');
    bindAccordion('btn-toggle-playbook-evidence', evidenceBody, 'icon-playbook-evidence-chevron-wrap');
    bindAccordion('btn-toggle-playbook-tech-details', techBody, 'icon-playbook-tech-chevron-wrap');

    const btnDrill = document.getElementById('btn-playbook-drill-legacy');
    if (btnDrill) {
        btnDrill.onclick = () => {
            closePlaybookModal();
            drillToLegacyAnomalies(_currentPlaybookIdx);
        };
    }

    if (modal) modal.classList.add('active');
    if (window.lucide) window.lucide.createIcons();
}

async function fetchIncidentNotesForModal(ev) {
    try {
        const params = new URLSearchParams({
            host_ip: ev.host_ip,
            scenario_key: ev.scenario_name || ''
        });
        const res = await fetch(`/api/incidents/notes?${params.toString()}`);
        if (!res.ok) throw new Error('Failed to load notes');
        const data = await res.json();
        ev.incident_status = data.status || 'open';
        ev.incident_latest_note = data.latest_note || '';
        ev.incident_note_count = data.note_count || 0;
        if (data.asset_contact) {
            ev.asset_contact = data.asset_contact;
            _renderPlaybookContactSummary(ev);
        }
        _renderPlaybookStatusBadge(ev.incident_status);
        _renderPlaybookNotesTimeline(data.notes || []);
    } catch (err) {
        const el = document.getElementById('playbook-notes-timeline');
        if (el) el.innerHTML = `<div style="font-size:0.8rem;color:#f87171;text-align:center;padding:8px 0;">載入備註紀錄失敗：${escapeHtml(err.message)}</div>`;
    }
}

async function savePlaybookAssetContact(ev) {
    const payload = {
        ip: ev.host_ip,
        alias_name: (document.getElementById('playbook-edit-alias')?.value || '').trim(),
        owner_name: (document.getElementById('playbook-edit-owner')?.value || '').trim(),
        department: (document.getElementById('playbook-edit-dept')?.value || '').trim(),
        vendor_name: (document.getElementById('playbook-edit-vendor')?.value || '').trim(),
        contact_info: (document.getElementById('playbook-edit-contact')?.value || '').trim(),
        device_role: (document.getElementById('playbook-edit-role')?.value || '').trim()
    };
    try {
        const res = await fetch('/api/asset-contacts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '儲存失敗');
        const updated = data.contact || payload;
        // Sync across all events sharing this host_ip
        (diagState.events || []).forEach(item => {
            if (item.host_ip === ev.host_ip) {
                item.asset_contact = updated;
                if (updated.name) item.host_alias = updated.name;
            }
        });
        ev.asset_contact = updated;
        if (updated.name) ev.host_alias = updated.name;
        _renderPlaybookContactSummary(ev);
        const editBox = document.getElementById('playbook-contact-edit-box');
        if (editBox) editBox.style.display = 'none';
        renderFilteredEquipmentList();
        fetchIpAliases();
        showToast(data.message || '已儲存負責人與維護廠商資訊', 'success', '聯絡資訊已同步');
    } catch (err) {
        showToast(err.message, 'error', '儲存失敗');
    }
}

async function saveIncidentNoteFromModal(ev) {
    const statusVal = document.getElementById('playbook-incident-status-select')?.value || 'open';
    const noteInput = document.getElementById('playbook-note-input');
    const noteText = (noteInput?.value || '').trim();
    const btn = document.getElementById('btn-save-incident-note');
    if (btn) btn.disabled = true;
    try {
        const res = await fetch('/api/incidents/notes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                host_ip: ev.host_ip,
                scenario_key: ev.scenario_name || '',
                status: statusVal,
                note: noteText
            })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '儲存失敗');
        ev.incident_status = data.incident_status || statusVal;
        ev.incident_latest_note = data.latest_note || '';
        ev.incident_note_count = data.note_count || 0;
        if (noteInput) noteInput.value = '';
        _renderPlaybookStatusBadge(ev.incident_status);
        _renderPlaybookNotesTimeline(data.notes || []);
        renderFilteredEquipmentList();
        showToast('已儲存廠商回覆與處理狀態（同步更新至異常設備清單）', 'success', '備註已儲存');
    } catch (err) {
        showToast(err.message, 'error', '儲存備註失敗');
    } finally {
        if (btn) btn.disabled = false;
    }
}

function copyVendorInquiryMessage(ev) {
    const nac = ev.athenac || {};
    const c = ev.asset_contact || {};
    const swPort = [nac.switch_name, nac.port_name].filter(Boolean).join(' / ') || '未納管';
    const targetsStr = (ev.targets || []).map(t => t.alias ? `${t.alias} (${t.ip})` : t.ip).join('、') || '外部網路';
    const portsStr = (ev.ports || []).map(p => p.name ? `${p.port} (${p.name})` : p.port).join('、') || '多種連接埠';
    const tiLines = (ev.threat_intel || []).map(ti =>
        `  - 外部 IP ${ti.ip}${ti.domain ? ` (${ti.domain})` : ''}：風險值 ${ti.risk_score} (${ti.risk_level || ''})${ti.risky_ports ? `、風險埠 [${ti.risky_ports}]` : ''}${ti.vulns ? `、弱點 ${ti.vulns}` : ''}`
    );

    const msg = [
        `您好，網路流量監控系統偵測到以下主機出現異常連線／風險事件，請協助確認原因與提供處置建議：`,
        ``,
        `【異常主機資訊】`,
        `• 主機名稱 / IP：${c.name || ev.host_alias || nac.hostname || ev.host_ip} (${ev.host_ip})`,
        `• 實體位置 (Switch/Port)：${swPort}`,
        c.owner_name || c.department ? `• 主機負責人 / 部門：${[c.owner_name, c.department].filter(Boolean).join(' / ')}` : null,
        c.vendor_name ? `• 維護廠商：${c.vendor_name}${c.contact_info ? ` (${c.contact_info})` : ''}` : null,
        ``,
        `【異常現象與時間】`,
        `• 風險情境：${ev.scenario_name} (${ev.category})`,
        `• 發生時段：${ev.time_window_label}（最後活動時間：${ev.last_ts}）`,
        `• 存取對象與服務：${targetsStr} [Port: ${portsStr}]`,
        `• 流量與連線規模：${formatBytes(ev.total_bytes)} / 共 ${formatNumber(ev.flow_count)} 筆連線`,
        `• 系統判定說明：${ev.reason_text}`,
        tiLines.length > 0 ? `• 外部情資與漏洞比對：\n${tiLines.join('\n')}` : null,
        ``,
        `再麻煩協助確認此主機當時執行的作業內容，或提供相關修補／處置解法，謝謝！`
    ].filter(x => x !== null).join('\n');

    copyTextToClipboard(msg).then(() => {
        const textSpan = document.getElementById('btn-playbook-copy-vendor-text');
        if (textSpan) {
            const orig = textSpan.innerText;
            textSpan.innerText = '已複製詢問廠商訊息！';
            setTimeout(() => { textSpan.innerText = orig; }, 2200);
        }
        showToast('已複製「詢問廠商訊息」至剪貼簿，可直接貼上至 LINE / Teams / Email', 'success', '複製成功');
    }).catch(err => {
        console.error('Copy vendor message failed:', err);
        showToast('複製失敗，請手動選取文字複製', 'error', '複製失敗');
    });
}

function copyTextToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.left = '-9999px';
            ta.style.top = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            if (ok) resolve();
            else reject(new Error('execCommand copy returned false'));
        } catch (e) {
            reject(e);
        }
    });
}

function copyPlaybookReport() {
    const ev = _filteredEventsList[_currentPlaybookIdx] || diagState.events[_currentPlaybookIdx];
    if (!ev) return;
    const nac = ev.athenac || {};
    const report = [
        `【智慧資安異常情境診斷與處置報告】`,
        `診斷基準: ${diagState.targetDate ? diagState.targetDate + ' 全日' : (diagState.timeLabel || '全時段')}`,
        `設備身分: ${ev.host_alias || nac.hostname || ev.host_ip} (${ev.host_ip})`,
        `MAC 位址: ${nac.mac || '未知'}`,
        `實體位置: ${(nac.switch_name || '')} ${(nac.port_name || '')}`.trim() || '未納管',
        `風險等級: ${ev.severity_label || ev.severity}`,
        `觸發情境: ${ev.scenario_name} (${ev.category})`,
        `白話原因: ${ev.reason_text}`,
        `連線規模: ${formatBytes(ev.total_bytes)} (${formatNumber(ev.flow_count)} 筆連線)，最後時間: ${ev.last_ts}`,
        `建議處置步驟:`,
        ...(ev.remediation_steps || []).map((s, i) => `  ${i + 1}. ${s.replace(/^\d+\.\s*/, '')}`)
    ].join('\n');

    navigator.clipboard.writeText(report).then(() => {
        const textSpan = document.getElementById('btn-playbook-copy-text');
        if (textSpan) {
            const orig = textSpan.innerText;
            textSpan.innerText = '已複製到剪貼簿！';
            setTimeout(() => { textSpan.innerText = orig; }, 2000);
        }
    }).catch(err => {
        console.error('Copy failed:', err);
    });
}

function closePlaybookModal() {
    const modal = document.getElementById('modal-diagnostic-playbook');
    if (modal) modal.classList.remove('active');
}

function drillToLegacyAnomalies(idx) {
    const ev = _filteredEventsList[idx] || diagState.events[idx];
    if (!ev) return;

    // Reset and populate drill-down anomalies filters with host IP (+ port if single)
    state.anomaliesFilters.conditions = [{ id: genConditionId(), field: 'any_ip', ipType: 'custom', val: ev.host_ip }];
    if (ev.drill_filters && ev.drill_filters.port) {
        state.anomaliesFilters.conditions.push({ id: genConditionId(), field: 'any_port', ipType: 'custom', val: ev.drill_filters.port });
    }
    state.anomaliesFilters.logic = 'AND';
    state.anomaliesFilters.flag = '';
    if (els.filterAnomaliesFlag) els.filterAnomaliesFlag.value = '';
    state.anomaliesPagination.offset = 0;

    renderConditions('anomalies');

    const titleEl = document.getElementById('drill-modal-title');
    const subEl = document.getElementById('drill-modal-subtitle');
    if (titleEl) titleEl.innerText = `底層流量明細與流向分析 — ${ev.host_ip}`;
    if (subEl) {
        const portText = (ev.drill_filters && ev.drill_filters.port) ? ` ｜ Port: ${ev.drill_filters.port}` : '';
        subEl.innerText = `情境：${ev.scenario_name || '異常情境'} ｜ 異常主機：${ev.host_ip}${portText}`;
    }

    const sankeyContainer = document.getElementById('drill-sankey-container');
    if (sankeyContainer) {
        sankeyContainer.innerHTML = `<div class="text-center text-muted py-5" style="padding: 80px 0;">正在繪製視覺化圖表...</div>`;
    }
    const drillChartSelect = document.getElementById('drill-chart-mode-select');
    if (drillChartSelect) drillChartSelect.value = 'sankey';
    const drillChartHint = document.getElementById('drill-chart-hint');
    if (drillChartHint) drillChartHint.innerText = '線寬代表傳輸量 (Bytes)，點擊節點可加入篩選';
    const sankeySummary = document.getElementById('drill-sankey-summary');
    if (sankeySummary) sankeySummary.innerText = '載入中...';
    const sankeyBody = document.getElementById('drill-sankey-body');
    if (sankeyBody) sankeyBody.style.display = 'block';
    const btnToggleSankey = document.getElementById('btn-toggle-drill-sankey');
    if (btnToggleSankey) {
        btnToggleSankey.innerHTML = '<i data-lucide="chevron-up" style="width: 13px; height: 13px;"></i><span>收合圖表</span>';
    }

    const modal = document.getElementById('modal-drill-details');
    if (modal) modal.classList.add('active');
    if (window.lucide) window.lucide.createIcons();

    fetchAnomalousReport();
}

// Scenario Rules Manager - Now Integrated into Traffic Audit (系統設定 -> 流量盤查)
async function openScenarioRulesModal() {
    switchView('audit');
    switchAuditSubtab('scenarios');
    await fetchScenariosList();
    if (window.lucide && typeof window.lucide.createIcons === 'function') window.lucide.createIcons();
}

function closeScenarioRulesModal() {
    // Legacy modal compatibility
}

function switchAuditSubtab(subtabName) {
    const btnScenarios = document.getElementById('btn-audit-subtab-scenarios');
    const btnLegacy = document.getElementById('btn-audit-subtab-legacy');
    const btnIntel = document.getElementById('btn-audit-subtab-intel');
    const panelScenarios = document.getElementById('audit-subpanel-scenarios');
    const panelLegacy = document.getElementById('audit-subpanel-legacy');
    const panelIntel = document.getElementById('audit-subpanel-intel');

    if (btnScenarios) btnScenarios.classList.remove('active');
    if (btnLegacy) btnLegacy.classList.remove('active');
    if (btnIntel) btnIntel.classList.remove('active');
    if (panelScenarios) panelScenarios.style.display = 'none';
    if (panelLegacy) panelLegacy.style.display = 'none';
    if (panelIntel) panelIntel.style.display = 'none';

    if (subtabName === 'scenarios') {
        if (btnScenarios) btnScenarios.classList.add('active');
        if (panelScenarios) panelScenarios.style.display = 'block';
        fetchScenariosList();
    } else if (subtabName === 'intel') {
        if (btnIntel) btnIntel.classList.add('active');
        if (panelIntel) panelIntel.style.display = 'block';
        fetchThreatIntelCache();
    } else {
        if (btnLegacy) btnLegacy.classList.add('active');
        if (panelLegacy) panelLegacy.style.display = 'block';
        fetchAuditRules();
        fetchAuditStatus();
    }
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
    }
}

async function fetchScenariosList() {
    try {
        const res = await fetch('/api/scenarios');
        if (!res.ok) throw new Error('無法取得情境規則清單');
        diagState.scenarios = await res.json();
        renderScenariosTable();
    } catch (err) {
        showScenarioStatus(err.message, 'error');
    }
}

function renderScenariosTable() {
    const tbody = document.getElementById('scenario-rules-tbody');
    if (!tbody) return;
    if (!diagState.scenarios.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted py-4">尚無任何智慧情資規則</td></tr>`;
        return;
    }

    const twLabel = { all: '全時段(24H)', work_hours: '上班(09-18)', off_hours: '非上班', late_night: '深夜(00-06)' };
    tbody.innerHTML = diagState.scenarios.map(sc => {
        const mb = sc.min_bytes ? `${Math.round(sc.min_bytes / (1024 * 1024))}MB` : '0MB(不限)';
        const condSummary = `${escapeHtml(sc.src_scope)} ➔ ${escapeHtml(sc.dst_scope)} | Port: ${escapeHtml(sc.ports || '不限(全埠)')} | 時段: ${twLabel[sc.time_window] || sc.time_window} | ≥${mb}`;
        const enabledBadge = sc.is_enabled
            ? `<span style="font-size:0.7rem;color:#34d399;font-weight:600;display:block;margin-top:2px;">啟用中</span>`
            : `<span style="font-size:0.7rem;color:#9ca3af;display:block;margin-top:2px;">已關閉</span>`;
        const rowOpacity = sc.is_enabled ? '1' : '0.55';
        return `
            <tr style="opacity: ${rowOpacity}; transition: opacity 0.2s;">
                <td style="padding: 8px 10px; text-align: center;">
                    <input type="checkbox" ${sc.is_enabled ? 'checked' : ''} onchange="toggleScenarioEnabled(${sc.id}, this.checked)" style="cursor:pointer; width: 16px; height: 16px; accent-color: var(--color-primary);" title="點擊開啟或關閉此規則">
                    ${enabledBadge}
                </td>
                <td style="padding: 8px 10px;">
                    <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(sc.name)}</div>
                    <div style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(sc.category)}</div>
                </td>
                <td style="padding: 8px 10px; text-align: center;">${getSeverityBadgeHtml(sc.severity)}</td>
                <td style="padding: 8px 10px; font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary);">
                    <div>${condSummary}</div>
                    ${sc.reason_template ? `<div style="font-family: var(--font-sans); font-size: 0.73rem; color: var(--text-muted); margin-top: 3px; max-width: 560px; white-space: normal;">${escapeHtml(sc.reason_template)}</div>` : ''}
                </td>
                <td style="padding: 8px 10px; text-align: right; white-space: nowrap;">
                    <button type="button" class="btn btn-secondary btn-sm" onclick="editScenarioItem(${sc.id})" style="padding: 3px 8px; font-size: 0.74rem;">編輯</button>
                    <button type="button" class="btn btn-danger btn-sm" onclick="deleteScenarioItem(${sc.id})" style="padding: 3px 8px; font-size: 0.74rem;">刪除</button>
                </td>
            </tr>
        `;
    }).join('');
}

function editScenarioItem(id) {
    const sc = diagState.scenarios.find(x => x.id === id);
    if (!sc) return;
    document.getElementById('sc-edit-id').value = sc.id;
    document.getElementById('sc-name').value = sc.name;
    document.getElementById('sc-category').value = sc.category;
    document.getElementById('sc-severity').value = sc.severity;
    document.getElementById('sc-time-window').value = sc.time_window || 'all';
    document.getElementById('sc-src-scope').value = sc.src_scope || 'any';
    document.getElementById('sc-dst-scope').value = sc.dst_scope || 'any';
    document.getElementById('sc-ports').value = sc.ports || '';
    document.getElementById('sc-min-mb').value = Math.round((sc.min_bytes || 0) / (1024 * 1024));
    document.getElementById('sc-reason').value = sc.reason_template || '';
    document.getElementById('sc-remediation').value = sc.remediation_steps || '';
    document.getElementById('scenario-form-title').innerText = `✏️ 編輯情境規則：${sc.name}`;
}

function clearScenarioForm() {
    document.getElementById('sc-edit-id').value = '';
    document.getElementById('form-scenario-rule').reset();
    document.getElementById('sc-src-scope').value = 'internal';
    document.getElementById('sc-dst-scope').value = 'any';
    document.getElementById('sc-min-mb').value = '0';
    document.getElementById('scenario-form-title').innerText = '➕ 新增自訂情境判斷規則';
}

function applyScenarioPreset(preset) {
    clearScenarioForm();
    if (preset === 'youtube') {
        document.getElementById('sc-name').value = '員工上班時間觀看 YouTube / 影音串流';
        document.getElementById('sc-category').value = '上班娛樂／影音偷懶';
        document.getElementById('sc-severity').value = 'behavior';
        document.getElementById('sc-time-window').value = 'work_hours';
        document.getElementById('sc-src-scope').value = 'internal';
        document.getElementById('sc-dst-scope').value = 'youtube';
        document.getElementById('sc-ports').value = '80,443';
        document.getElementById('sc-min-mb').value = '5';
        document.getElementById('sc-reason').value = '上班時段（09:00-18:00）偵測到員工電腦大量存取 YouTube / 串流影音服務，疑似上班摸魚並佔用對外頻寬。';
        document.getElementById('sc-remediation').value = '1. 確認該員工作職掌是否需要存取影音網站。\n2. 若屬非公務用途，請提醒改善或於防火牆設定影音限速政策。';
    } else if (preset === 'latenight') {
        document.getElementById('sc-name').value = '重要主機深夜異常存取';
        document.getElementById('sc-category').value = '重要資產異常時段存取';
        document.getElementById('sc-severity').value = 'high';
        document.getElementById('sc-time-window').value = 'late_night';
        document.getElementById('sc-src-scope').value = 'any';
        document.getElementById('sc-dst-scope').value = '192.168.10.10,192.168.10.20';
        document.getElementById('sc-ports').value = '3306,3389,22,445';
        document.getElementById('sc-min-mb').value = '0';
        document.getElementById('sc-reason').value = '深夜無人維運時段（00:00-06:00）偵測到主機連線存取核心資料庫或伺服器管理埠，疑似帳號盜用或未授權存取。';
        document.getElementById('sc-remediation').value = '1. 確認是否有核准夜間維護作業。\n2. 檢查來源主機與使用者登入紀錄，必要時立即停用帳號並阻斷連線。';
    } else if (preset === 'exfil') {
        document.getElementById('sc-name').value = '內網對外異常巨量上傳';
        document.getElementById('sc-category').value = '疑似資料外洩大流量';
        document.getElementById('sc-severity').value = 'high';
        document.getElementById('sc-time-window').value = 'all';
        document.getElementById('sc-src-scope').value = 'internal';
        document.getElementById('sc-dst-scope').value = 'external';
        document.getElementById('sc-ports').value = '';
        document.getElementById('sc-min-mb').value = '15';
        document.getElementById('sc-reason').value = '內網設備對外部網際網路傳出異常大量封包，疑似將內部敏感檔案外傳至不明主機。';
        document.getElementById('sc-remediation').value = '1. 檢查目的 IP 是否為公司核准之雲端服務。\n2. 聯繫該設備人員確認傳輸內容並保留連線紀錄。';
    } else if (preset === 'unknown') {
        document.getElementById('sc-name').value = '未納管未知新設備連線';
        document.getElementById('sc-category').value = '新進未知資產';
        document.getElementById('sc-severity').value = 'low';
        document.getElementById('sc-time-window').value = 'all';
        document.getElementById('sc-src-scope').value = '192.168.30.220,192.168.30.221,internal';
        document.getElementById('sc-dst-scope').value = 'any';
        document.getElementById('sc-ports').value = '80,443,8080';
        document.getElementById('sc-min-mb').value = '0';
        document.getElementById('sc-reason').value = '偵測到尚未在 AtheNAC 或網管資產庫註冊的新設備正在發起日常通訊，可能為訪客自攜設備 (BYOD) 或未登記之新進電腦。';
        document.getElementById('sc-remediation').value = '1. 檢視該設備的 MAC 位址與 Switch 連接埠。\n2. 若為訪客設備指引其連線至 Guest VLAN。\n3. 確認主機使用者身分後登記至 AtheNAC。';
    }
}

async function submitScenarioForm() {
    const editId = document.getElementById('sc-edit-id').value;
    const minMb = parseInt(document.getElementById('sc-min-mb').value || '0', 10);
    const payload = {
        name: document.getElementById('sc-name').value.trim(),
        category: document.getElementById('sc-category').value.trim(),
        severity: document.getElementById('sc-severity').value,
        time_window: document.getElementById('sc-time-window').value,
        src_scope: document.getElementById('sc-src-scope').value.trim() || 'any',
        dst_scope: document.getElementById('sc-dst-scope').value.trim() || 'any',
        ports: document.getElementById('sc-ports').value.trim(),
        min_bytes: Math.max(0, minMb) * 1024 * 1024,
        reason_template: document.getElementById('sc-reason').value.trim(),
        remediation_steps: document.getElementById('sc-remediation').value.trim(),
        is_enabled: true
    };
    try {
        const url = editId ? `/api/scenarios/${editId}` : '/api/scenarios';
        const method = editId ? 'PUT' : 'POST';
        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '儲存失敗');
        showScenarioStatus(data.message || '儲存成功', 'success');
        clearScenarioForm();
        await fetchScenariosList();
        fetchSmartDiagnostics();
        fetchAuditRules();
    } catch (err) {
        showScenarioStatus(err.message, 'error');
    }
}

async function toggleScenarioEnabled(id, checked) {
    const sc = diagState.scenarios.find(x => x.id === id);
    if (!sc) return;
    try {
        await fetch(`/api/scenarios/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...sc, is_enabled: checked })
        });
        await fetchScenariosList();
        fetchSmartDiagnostics();
        fetchAuditRules();
    } catch (err) {
        showScenarioStatus(err.message, 'error');
    }
}

async function deleteScenarioItem(id) {
    if (!confirm('確定要刪除此智慧情境規則嗎？')) return;
    try {
        const res = await fetch(`/api/scenarios/${id}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('刪除失敗');
        await fetchScenariosList();
        fetchSmartDiagnostics();
        fetchAuditRules();
    } catch (err) {
        showScenarioStatus(err.message, 'error');
    }
}

async function resetDefaultScenarios() {
    if (!confirm('確定要重設並還原 5 大內建智慧情境範本嗎？')) return;
    try {
        const res = await fetch('/api/scenarios/reset-defaults', { method: 'POST' });
        const data = await res.json();
        showScenarioStatus(data.message || '已還原預設範本', 'success');
        await fetchScenariosList();
        fetchSmartDiagnostics();
        fetchAuditRules();
    } catch (err) {
        showScenarioStatus(err.message, 'error');
    }
}

function showScenarioStatus(msg, type) {
    const el = document.getElementById('scenario-form-status');
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    el.style.backgroundColor = type === 'success' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)';
    el.style.color = type === 'success' ? '#34d399' : '#f87171';
    el.style.border = type === 'success' ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(239, 68, 68, 0.3)';
    setTimeout(() => { el.style.display = 'none'; }, 4000);
}

// AtheNAC Settings Functions
async function fetchAthenacSettings() {
    try {
        const res = await fetch('/api/settings/athenac');
        if (!res.ok) return;
        const data = await res.json();
        const urlEl = document.getElementById('input-athenac-url');
        const keyEl = document.getElementById('input-athenac-apikey');
        const userEl = document.getElementById('input-athenac-username');
        const mockEl = document.getElementById('checkbox-athenac-mock');
        if (urlEl) urlEl.value = data.api_url || 'https://192.168.25.180:8001';
        if (keyEl) keyEl.placeholder = data.has_api_key ? `已設定 (${data.api_key_masked})` : '請輸入 PIXIS X-Api-Key';
        if (userEl) userEl.value = data.username || '';
        if (mockEl) mockEl.checked = data.mock_fallback !== false;
    } catch (err) {
        console.error('Failed to load AtheNAC settings:', err);
    }
}

async function saveAthenacSettings() {
    const payload = {
        api_url: document.getElementById('input-athenac-url')?.value.trim() || 'https://192.168.25.180:8001',
        api_key: document.getElementById('input-athenac-apikey')?.value.trim() || '',
        username: document.getElementById('input-athenac-username')?.value.trim() || '',
        password: document.getElementById('input-athenac-password')?.value.trim() || '',
        mock_fallback: document.getElementById('checkbox-athenac-mock')?.checked ?? true
    };
    try {
        const res = await fetch('/api/settings/athenac', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        showAthenacStatus(data.message || '設定已儲存', 'success');
        fetchAthenacSettings();
    } catch (err) {
        showAthenacStatus(err.message, 'error');
    }
}

async function testAthenacConnection() {
    try {
        const res = await fetch('/api/settings/athenac/test', { method: 'POST' });
        const data = await res.json();
        const sample = data.sample || {};
        showAthenacStatus(`${data.message} (範例回傳: HostName=${sample.hostname || 'N/A'}, MAC=${sample.mac || 'N/A'}, Switch=${sample.switch_name || 'N/A'} ${sample.port_name || ''})`, data.status === 'connected' ? 'success' : 'info');
    } catch (err) {
        showAthenacStatus(`測試失敗: ${err.message}`, 'error');
    }
}

function showAthenacStatus(msg, type) {
    const el = document.getElementById('athenac-settings-status');
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else if (type === 'info') {
        el.style.backgroundColor = 'rgba(14, 165, 233, 0.15)';
        el.style.color = '#38bdf8';
        el.style.border = '1px solid rgba(14, 165, 233, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
}

// ---------------- External Threat Intelligence (Criminal IP / VirusTotal / Shodan) Functions ----------------
async function fetchThreatIntelSettings() {
    try {
        const res = await fetch('/api/settings/threat-intel');
        if (!res.ok) return;
        const data = await res.json();
        const cipEl = document.getElementById('input-criminalip-apikey');
        const vtEl = document.getElementById('input-virustotal-apikey');
        const shodanEl = document.getElementById('input-shodan-apikey');
        const limitEl = document.getElementById('input-intel-batch-limit');

        if (cipEl) {
            cipEl.value = '';
            cipEl.placeholder = data.has_criminalip_key ? `已設定 (${data.criminalip_key_masked})` : '請輸入 Criminal IP x-api-key (留空則使用備援)';
        }
        if (vtEl) {
            vtEl.value = '';
            vtEl.placeholder = data.has_virustotal_key ? `已設定 (${data.virustotal_key_masked})` : '免費版每日 500 次查詢 (HTTP 429 自動切換)';
        }
        if (shodanEl) {
            shodanEl.value = '';
            shodanEl.placeholder = data.has_shodan_key ? `已設定 (${data.shodan_key_masked})` : '選填，未填時自動以免費 InternetDB 保底';
        }
        if (limitEl && data.batch_limit) {
            limitEl.value = data.batch_limit;
        }
        const badgeCount = document.getElementById('badge-intel-db-count');
        if (badgeCount && data.total_cached_ips !== undefined) {
            badgeCount.innerText = data.total_cached_ips;
        }
    } catch (err) {
        console.error('Failed to load Threat Intel settings:', err);
    }
}

async function saveThreatIntelSettings() {
    const payload = {
        criminalip_api_key: document.getElementById('input-criminalip-apikey')?.value.trim() || '',
        virustotal_api_key: document.getElementById('input-virustotal-apikey')?.value.trim() || '',
        shodan_api_key: document.getElementById('input-shodan-apikey')?.value.trim() || '',
        batch_limit: parseInt(document.getElementById('input-intel-batch-limit')?.value || '25', 10)
    };
    try {
        const res = await fetch('/api/settings/threat-intel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '儲存失敗');
        showThreatIntelSettingsStatus(data.message || '設定已儲存', 'success');
        showToast(data.message || '外部威脅情資設定已儲存', 'success', '設定已更新');
        fetchThreatIntelSettings();
    } catch (err) {
        showThreatIntelSettingsStatus(err.message, 'error');
    }
}

async function testThreatIntelConnection() {
    const btn = document.getElementById('btn-test-threat-intel');
    if (btn) btn.disabled = true;
    showThreatIntelSettingsStatus('正在測試外部威脅情資 API 查詢與自動降級備援機制...', 'info');
    try {
        const res = await fetch('/api/settings/threat-intel/test?test_ip=1.1.1.1', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '測試失敗');
        showThreatIntelSettingsStatus(data.message, 'success');
        showToast(data.message, 'success', '情資 API 測試成功');
        fetchThreatIntelCache();
    } catch (err) {
        showThreatIntelSettingsStatus(`測試失敗: ${err.message}`, 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

function showThreatIntelSettingsStatus(msg, type) {
    const el = document.getElementById('threat-intel-settings-status');
    if (!el) return;
    el.style.display = 'block';
    el.innerText = msg;
    if (type === 'success') {
        el.style.backgroundColor = 'rgba(16, 185, 129, 0.15)';
        el.style.color = '#34d399';
        el.style.border = '1px solid rgba(16, 185, 129, 0.3)';
    } else if (type === 'info') {
        el.style.backgroundColor = 'rgba(14, 165, 233, 0.15)';
        el.style.color = '#38bdf8';
        el.style.border = '1px solid rgba(14, 165, 233, 0.3)';
    } else {
        el.style.backgroundColor = 'rgba(239, 68, 68, 0.15)';
        el.style.color = '#f87171';
        el.style.border = '1px solid rgba(239, 68, 68, 0.3)';
    }
}

async function fetchThreatIntelCache() {
    try {
        const search = document.getElementById('input-search-intel-cache')?.value.trim() || '';
        const riskLevel = document.getElementById('select-filter-intel-risk')?.value || '';
        const params = new URLSearchParams();
        if (search) params.set('search', search);
        if (riskLevel) params.set('risk_level', riskLevel);

        const res = await fetch(`/api/threat-intel/cache?${params.toString()}`);
        if (!res.ok) return;
        const data = await res.json();

        const setEl = (id, v) => { const e = document.getElementById(id); if (e) e.innerText = v; };
        setEl('badge-intel-db-count', data.total || 0);
        setEl('intel-stat-total', data.total || 0);
        setEl('intel-stat-high', data.high_risk_count || 0);
        setEl('intel-stat-ports', data.risky_port_count || 0);

        const tbody = document.getElementById('threat-intel-cache-tbody');
        if (!tbody) return;
        const records = data.records || [];
        const selectAllChk = document.getElementById('chk-select-all-intel');
        if (selectAllChk) selectAllChk.checked = false;
        if (records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted py-4">目前尚無符合條件的外部 IP 情資快取紀錄</td></tr>`;
            return;
        }

        tbody.innerHTML = records.map(r => {
            const lvl = (r.risk_level || 'safe').toLowerCase();
            let badgeStyle = 'background:rgba(16,185,129,0.16);color:#34d399;border:1px solid rgba(16,185,129,0.35);';
            let lvlText = `🟢 安全 (${r.risk_score})`;
            if (lvl === 'critical') {
                badgeStyle = 'background:rgba(239,68,68,0.22);color:#f87171;border:1px solid rgba(239,68,68,0.5);';
                lvlText = `🔴 極高危 (${r.risk_score})`;
            } else if (lvl === 'high') {
                badgeStyle = 'background:rgba(239,68,68,0.18);color:#f87171;border:1px solid rgba(239,68,68,0.4);';
                lvlText = `🔴 高危 (${r.risk_score})`;
            } else if (lvl === 'medium') {
                badgeStyle = 'background:rgba(245,158,11,0.18);color:#fbbf24;border:1px solid rgba(245,158,11,0.4);';
                lvlText = `🟠 中危 (${r.risk_score})`;
            } else if (lvl === 'low') {
                badgeStyle = 'background:rgba(14,165,233,0.16);color:#38bdf8;border:1px solid rgba(14,165,233,0.35);';
                lvlText = `🟡 低危 (${r.risk_score})`;
            }

            const riskyPortsHtml = r.risky_ports
                ? r.risky_ports.split(',').filter(Boolean).map(p => `<span class="badge" style="background:rgba(239,68,68,0.16);color:#fca5a5;border:1px solid rgba(239,68,68,0.35);font-family:var(--font-mono);font-size:0.73rem;margin:1px 2px;padding:1px 6px;">⚠️ ${escapeHtml(p)}</span>`).join(' ')
                : '<span class="text-muted">無高危埠</span>';

            const importBtnHtml = r.in_scenarios
                ? `<button type="button" class="btn btn-secondary btn-sm" onclick="importSingleIntelToScenario('${escapeHtml(r.ip)}')" style="padding: 3px 8px; font-size: 0.72rem; margin-right: 4px; color: #34d399; border-color: rgba(16, 185, 129, 0.45);" title="已在智慧情資規則庫中（點擊可同步更新最新情資與風險埠說明）">✅ 已在規則庫</button>`
                : `<button type="button" class="btn btn-primary btn-sm" onclick="importSingleIntelToScenario('${escapeHtml(r.ip)}')" style="padding: 3px 8px; font-size: 0.72rem; margin-right: 4px;" title="將此 IP 匯入智慧情資規則庫（目標 Port 預設留空不限，風險埠號寫入條件說明）">➕ 匯入規則庫</button>`;

            return `
                <tr>
                    <td style="padding: 9px 10px; text-align: center;">
                        <input type="checkbox" class="chk-intel-item" value="${escapeHtml(r.ip)}" style="cursor: pointer; accent-color: var(--color-primary);">
                    </td>
                    <td style="padding: 9px 12px; font-family: var(--font-mono); font-weight: 600; color: var(--text-primary);">
                        <div>${escapeHtml(r.ip)}</div>
                        ${r.country || r.org ? `<div style="font-size:0.72rem;color:var(--text-muted);font-weight:400;">${escapeHtml([r.country, r.org].filter(Boolean).join(' · '))}</div>` : ''}
                    </td>
                    <td style="padding: 9px 12px; font-family: var(--font-mono); color: #a5b4fc;">
                        ${r.domain ? escapeHtml(r.domain) : '<span class="text-muted">(無反解 Domain)</span>'}
                    </td>
                    <td style="padding: 9px 12px; text-align: center;">
                        <span class="badge" style="${badgeStyle}padding:3px 8px;font-size:0.75rem;border-radius:6px;">${lvlText}</span>
                        <div style="font-size:0.68rem;color:var(--text-muted);margin-top:2px;">In: ${escapeHtml(r.inbound_score || '-')} / Out: ${escapeHtml(r.outbound_score || '-')}</div>
                    </td>
                    <td style="padding: 9px 12px;">${riskyPortsHtml}</td>
                    <td style="padding: 9px 12px; font-size: 0.76rem; color: var(--text-secondary);">
                        ${r.open_ports ? `<div>開放 Port: <code>${escapeHtml(r.open_ports)}</code></div>` : ''}
                        ${r.vulns ? `<div style="color:#f87171;">弱點: ${escapeHtml(r.vulns)}</div>` : ''}
                        <div style="color:var(--text-muted);margin-top:2px;">${escapeHtml(r.summary || '')}</div>
                    </td>
                    <td style="padding: 9px 12px; text-align: center;">
                        <span class="badge" style="background:rgba(99,102,241,0.16);color:#c7d2fe;border:1px solid rgba(99,102,241,0.32);font-size:0.72rem;padding:2px 7px;">${escapeHtml(r.provider || 'DB')}</span>
                    </td>
                    <td style="padding: 9px 12px; font-family: var(--font-mono); font-size: 0.76rem; color: var(--text-muted);">
                        ${escapeHtml(r.updated_at || r.queried_at || '-')}
                    </td>
                    <td style="padding: 9px 12px; text-align: right; white-space: nowrap;">
                        ${importBtnHtml}
                        <button type="button" class="btn btn-secondary btn-sm" onclick="reQueryThreatIntelItem('${escapeHtml(r.ip)}')" style="padding: 3px 7px; font-size: 0.72rem; margin-right: 4px;" title="強制重新向 API 查詢">重查</button>
                        <button type="button" class="btn btn-danger btn-sm" onclick="deleteThreatIntelItem('${escapeHtml(r.ip)}')" style="padding: 3px 7px; font-size: 0.72rem;">刪除</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading threat intel cache:', err);
    }
}

async function manualLookupThreatIntel() {
    const inputEl = document.getElementById('input-manual-intel-target');
    const btn = document.getElementById('btn-manual-intel-query');
    const statusEl = document.getElementById('intel-lookup-status');
    const target = inputEl?.value.trim() || '';
    if (!target) {
        alert('請輸入要查詢的外部 IP 或 Domain！');
        return;
    }
    if (btn) btn.disabled = true;
    if (statusEl) {
        statusEl.style.display = 'block';
        statusEl.style.background = 'rgba(99, 102, 241, 0.15)';
        statusEl.style.color = '#a5b4fc';
        statusEl.innerText = `正在查詢「${target}」之外部威脅情資並寫入資料庫...`;
    }
    try {
        const res = await fetch('/api/threat-intel/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, force_refresh: true })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '查詢失敗');
        const rec = data.record || {};
        const msg = `已存入 DB！IP: ${rec.ip}｜Domain: ${rec.domain || '無'}｜風險值: ${rec.risk_score} (${rec.inbound_score})｜風險埠: ${rec.risky_ports || '無'}｜來源: ${rec.provider}`;
        if (statusEl) {
            statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
            statusEl.style.color = '#34d399';
            statusEl.innerText = msg;
        }
        showToast(msg, 'success', '情資查詢已存入 DB');
        if (inputEl) inputEl.value = '';
        fetchThreatIntelCache();
        fetchAuditMatches();
        fetchSmartDiagnostics();
    } catch (err) {
        if (statusEl) {
            statusEl.style.background = 'rgba(239, 68, 68, 0.15)';
            statusEl.style.color = '#f87171';
            statusEl.innerText = `查詢失敗: ${err.message}`;
        }
        showToast(err.message, 'error', '查詢失敗');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function reQueryThreatIntelItem(ip) {
    try {
        showToast(`正在重新向 API 查詢 ${ip} 最新情資...`, 'info', '重新查詢中');
        const res = await fetch('/api/threat-intel/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: ip, force_refresh: true })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '重查失敗');
        const rec = data.record || {};
        showToast(`${ip} 已更新！風險值 ${rec.risk_score}，風險埠 [${rec.risky_ports || '無'}] (${rec.provider})`, 'success', '情資已更新');
        fetchThreatIntelCache();
        fetchAuditMatches();
        fetchSmartDiagnostics();
    } catch (err) {
        showToast(err.message, 'error', '重查失敗');
    }
}

async function deleteThreatIntelItem(ip) {
    if (!confirm(`確定要從威脅情資資料庫移除 ${ip} 嗎？（移除後下次盤查遇到此 IP 將重新呼叫 API 查詢）`)) return;
    try {
        const res = await fetch(`/api/threat-intel/cache/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('刪除失敗');
        showToast(`已從情資資料庫移除 ${ip}`, 'success', '已刪除');
        fetchThreatIntelCache();
    } catch (err) {
        showToast(err.message, 'error', '刪除失敗');
    }
}

async function importScenariosFromExcelFile(file) {
    const reader = new FileReader();
    reader.onload = async (ev) => {
        try {
            const dataUrl = String(ev.target.result || '');
            const base64Content = dataUrl.includes(',') ? dataUrl.split(',')[1] : dataUrl;
            const res = await fetch('/api/scenarios/import-excel', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: file.name,
                    content_base64: base64Content
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || '匯入失敗');
            showToast(data.message || `已成功匯入情資規則`, 'success', 'EXCEL 規則匯入完成');
            fetchScenariosList();
            fetchSmartDiagnostics();
            fetchAuditRules();
        } catch (err) {
            showToast(err.message, 'error', '匯入失敗');
        }
    };
    reader.readAsDataURL(file);
}

async function importSingleIntelToScenario(ip) {
    if (!ip) return;
    try {
        const res = await fetch('/api/threat-intel/import-to-scenarios', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: [ip] })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '匯入智慧情資規則庫失敗');
        showToast(data.message || `已將 ${ip} 匯入智慧情資規則庫（目標 Port 留空不限，風險埠已寫入條件說明）`, 'success', '已匯入規則庫');
        fetchThreatIntelCache();
        fetchScenariosList();
        fetchSmartDiagnostics();
        fetchAuditRules();
    } catch (err) {
        showToast(err.message, 'error', '匯入失敗');
    }
}

async function batchImportSelectedIntelToScenarios() {
    const checked = Array.from(document.querySelectorAll('.chk-intel-item:checked')).map(cb => cb.value).filter(Boolean);
    if (checked.length === 0) {
        showToast('請先在下方清單左側勾選要匯入智慧情資規則庫的外部 IP！', 'warning', '尚未勾選 IP');
        return;
    }
    try {
        const res = await fetch('/api/threat-intel/import-to-scenarios', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips: checked })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || '批次匯入智慧情資規則庫失敗');
        showToast(data.message || `已將 ${checked.length} 筆 IP 批次匯入智慧情資規則庫`, 'success', '批次匯入完成');
        fetchThreatIntelCache();
        fetchScenariosList();
        fetchSmartDiagnostics();
        fetchAuditRules();
    } catch (err) {
        showToast(err.message, 'error', '批次匯入失敗');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initSmartDiagnosticsUI();
});


// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*
 ZykosConsolidacion_AutorCentrado.sol - Contrato unificado ZKS
 - ERC20 100M ZKS
 - 10 lotes x 10 pools (1M c/pool)
 - Distribución por pool: 10% Airdrops, 90% Venta/Liquidez
 - Distribución por lote: 50% Autor (inmediato), 50% Autor (bloqueado)
 - Servicios:
      * Internaciones: desbloqueo a los 180 días del deploy
      * Telemedicina: requiere PSYKooD online (flag one-way)
 - PSYKOSWorld / PSYKooD:
      * Pago on-portal SOLO en ZKS
      * Membresía: prepago, lock-to-access y activación por voucher EIP-712
      * Consumo exige holdear ZKS >= minHoldForConsume
 - 
 - Seguridad: Ownable, Pausable, ReentrancyGuard, bloqueo ETH/BNB, rescueTokens(no ZKS)
*/

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";


contract ZykosConsolidacion_AutorCentrado is ERC20, Ownable, Pausable, ReentrancyGuard {
    using ECDSA for bytes32;

    // --- Supply & estructura ---
    uint256 public constant TOTAL_SUPPLY    = 100_000_000 * 1e18;
    uint256 public constant POOL_SIZE       = 1_000_000  * 1e18;
    uint256 public constant MAX_LOTES       = 10;
    uint256 public constant POOLS_PER_LOTE  = 10;
    uint256 public constant MAX_POOLS       = MAX_LOTES * POOLS_PER_LOTE;

    // --- Distribución por pool/lote (porcentajes fijos) ---
    // por lote
    uint256 private constant PCT_AIRDROP     = 10; // por pool
    uint256 private constant PCT_VENTA_LIQ   = 60; // por pool
    
    // --- Estado de liberación ---
    uint256 public lotesLiberados;
    uint256 public poolActual;
    uint256 public lastPoolLiberationTime;
    uint256 public inactivityPeriod = 7 days;

    // --- Direcciones de distribución ---
    
    address public airdropVault;
    address public venta;
    
    // --- Servicios / App ---
    
    address public treasury; // Recibe los fees por servicio, que ahora van al autor
    
    // --- Membresías ---
    mapping(address => uint256) public membershipUntil;
    uint256 public pricePer90DaysZKS = 5_000 * 1e18;
    
    struct Lock { uint256 amount; uint64 since; bool active; }
    mapping(address => Lock) public membershipLock;
    uint256 public minStakeForAccess = 10_000 * 1e18;
    
    uint256 public minHoldForConsume = 1_000 * 1e18;

    // --- Vouchers EIP-712 ---
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 private constant MEMBERSHIP_TYPEHASH = keccak256(
        "MembershipVoucher(address user,uint256 daysPaid,uint256 nonce,uint256 deadline)"
    );
    mapping(address => uint256) public nonces;
    address public voucherSigner;

    
    // --- Eventos ---
    event LoteLiberado(uint256 indexed numeroLote);
    event PoolLiberado(uint256 indexed numeroPool, uint256 montoTotalPool, uint256 paraAirdrop, uint256 paraVenta, bytes32 motivo);
    event PSYKooDOnline();
    event MembershipPurchased(address indexed user, uint256 daysPaid, uint256 expiresAt, uint256 paidZKS);
    event MembershipLocked(address indexed user, uint256 amount);
    event MembershipUnlocked(address indexed user, uint256 amount);
    event MembershipActivatedByVoucher(address indexed user, uint256 daysPaid, uint256 nonce, uint256 deadline);
    event ServicioPagado(address indexed usuario, address indexed nodo, uint256 precioBase, uint256 totalPagado);
    event InactivityPeriodUpdated(uint256 newSeconds);
    event TreasuryUpdated(address t);
    event VoucherSignerUpdated(address s);
    event ParamsUpdated(uint256 pricePer90DaysZKS, uint256 minStakeForAccess, uint256 minHoldForConsume);
    event AutorVaultUpdated(address newVault);
    event AutorShareUnlocked(uint256 indexed loteNumber, uint256 amount);


    constructor(
        address _autor,
        address _autorVault,
        address _nodosTreasury,
        address _airdropVault,
        address _venta,
        address _treasury,
        address _voucherSigner
    ) ERC20("ZykosConsolidacion", "ZKS") Ownable(msg.sender) {
        require(_autor != address(0) && _nodosTreasury != address(0) && _airdropVault != address(0) && _venta != address(0), "addr zero");
        require(_treasury != address(0) && _voucherSigner != address(0), "addr zero");
        require(_autorVault != address(0), "addr zero");

        autor = _autor;
        autorVault = _autorVault;
       nodosTreasury=_nodosTreasuryRT190426392SG
        venta = _venta;
        treasury = _treasury;
        voucherSigner = _voucherSigner;
        
        deploymentTime = block.timestamp;
        _mint(address(this), TOTAL_SUPPLY);

        uint256 chainId;
        assembly { chainId := chainid() }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("ZykosMembership")),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );

        _liberarPoolInternal(true);
    }
    
    // =========================
    //   PAUSABLE
    // =========================
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    function _update(address from, address to, uint256 value) internal override(ERC20) {
        require(!paused(), "ERC20: pausable");
        super._update(from, to, value);
    }

    // --- Modificadores de servicio ---
    modifier onlyWhenInternaciones() {
        require(block.timestamp >= deploymentTime + 120 days, "Internaciones bloqueadas 120d");
        _;
    }
    modifier onlyWhenTelemedicina() {
        require(cicudOnline, "Telemedicina requiere PSYKooD online");
        _;
    }

    // --- Bloqueo ETH/BNB y fallback ---
    receive() external payable { revert("ONLY_ZKS"); }
    fallback() external payable { revert("ONLY_ZKS"); }

    // =========================
    //   LIBERACION DE POOLS
    // =========================
    function liberarPool() external {
        require(!paused(), "Contract is paused");
        require(poolActual < MAX_POOLS, "Todos los pools liberados");
        if (poolActual > 0) {
            require(balanceOf(venta) == 0, "Pool anterior con saldo en venta");
        }
        _liberarPoolInternal(true);
    }

    function liberarPoolPorInactividad() external {
        require(!paused(), "Contract is paused");
        require(poolActual < MAX_POOLS, "Todos los pools liberados");
        require(block.timestamp >= lastPoolLiberationTime + inactivityPeriod, "Inactividad insuficiente");
        require(balanceOf(venta) > 0, "Pool anterior ya agotado");
        _liberarPoolInternal(false);
    }

    function _liberarPoolInternal(bool agotado) internal {
        // Distribución del Lote completo de 10M
        if ((poolActual % POOLS_PER_LOTE) == 0) {
            uint256 loteAmount = 10 * POOL_SIZE;
            uint256 paraAutorLote = (loteAmount * PCT_AUTOR) / 100; // 25% del lote
            uint256 paraNodosLote = (loteAmount * PCT_NODOS_TRSY) / 100; // 5% del lote
            
            // 50% para el autor inmediatamente, 50% bloqueado
            _transfer(address(this), autor, paraAutorLote / 2);
            _transfer(address(this), autorVault, paraAutorLote / 2);
            
            _transfer(address(this), nodosTreasury, paraNodosLote);
            
            lotesLiberados++;
            emit LoteLiberado(lotesLiberados);
        }
        
        // Distribución del Pool actual de 1M
        uint256 montoPool = POOL_SIZE;
        uint256 paraAirdrop = (montoPool * PCT_AIRDROP) / 100;
        uint256 paraVenta = montoPool - paraAirdrop;

        _transfer(address(this), airdropVault, paraAirdrop);
        _transfer(address(this), venta, paraVenta);

        poolActual++;
        lastPoolLiberationTime = block.timestamp;
        
        emit PoolLiberado(poolActual, montoPool, paraAirdrop, paraVenta, agotado ? bytes32("AGOTADO") : bytes32("INACTIVIDAD"));
    }

    // Desbloqueo de fondos del autor al final del lote
    function liberarFondosAutor() external onlyOwner {
        require(lotesLiberados > 0, "No hay lotes liberados");
        require(lotesLiberados == poolActual / POOLS_PER_LOTE, "Lote no completado");
        require(balanceOf(autorVault) > 0, "No hay fondos en la boveda");
        
        uint256 saldo = balanceOf(autorVault);
        _transfer(autorVault, autor, saldo);
        emit AutorShareUnlocked(lotesLiberados, saldo);
    }

    // =========================
    //      SERVICIOS (ZKS)
    // =========================

    function pagarServicio(address nodo, uint256 precioBaseZKS)
        external
        nonReentrant
        whenNotPaused
    {
        require(nodo != address(0), "Nodo invalido");
        require(precioBaseZKS > 0, "Precio 0");
        require(balanceOf(msg.sender) >= minHoldForConsume, "Debe holdear ZKS para consumir");
        
        uint256 feeTotal = (precioBaseZKS * FEE_TOTAL_BPS) / BPS_DENOM;
        uint256 totalPagado = precioBaseZKS + feeTotal;
        
        _spendAllowance(msg.sender, address(this), totalPagado);
        _transfer(msg.sender, address(this), totalPagado);
        
        _transfer(address(this), nodo, precioBaseZKS); // Pago al nodo
        _transfer(address(this), autor, feeTotal);    // Fee total para el autor
        
        emit ServicioPagado(msg.sender, nodo, precioBaseZKS, totalPagado);
    }
    
    function pagarInternacion(address nodo, uint256 precioBaseZKS)
        external
        onlyWhenInternaciones
        whenNotPaused
    {
        pagarServicio(nodo, precioBaseZKS);
    }

    function pagarTelemedicina(address nodo, uint256 precioBaseZKS)
        external
        onlyWhenTelemedicina
        whenNotPaused
    {
        pagarServicio(nodo, precioBaseZKS);
    }

    // =========================
    //      MEMBRESIAS
    // =========================
    function buyMembership(uint256 daysPaid) external nonReentrant whenNotPaused {
        require(daysPaid > 0 && daysPaid <= 365, "Rango invalido");
        uint256 cost = (pricePer90DaysZKS * daysPaid) / 90;
        _spendAllowance(msg.sender, address(this), cost);
        _transfer(msg.sender, treasury, cost);
        uint256 base = membershipUntil[msg.sender] > block.timestamp ? membershipUntil[msg.sender] : block.timestamp;
        membershipUntil[msg.sender] = base + daysPaid * 1 days;
        emit MembershipPurchased(msg.sender, daysPaid, membershipUntil[msg.sender], cost);
    }
    
    function lockForAccess(uint256 amount) external nonReentrant whenNotPaused {
        require(amount >= minStakeForAccess, "Stake insuficiente");
        _spendAllowance(msg.sender, address(this), amount);
        _transfer(msg.sender, address(this), amount);
        membershipLock[msg.sender] = Lock({ amount: amount, since: uint64(block.timestamp), active: true });
        emit MembershipLocked(msg.sender, amount);
    }

    function unlockAccess() external nonReentrant whenNotPaused {
        Lock memory l = membershipLock[msg.sender];
        require(l.active, "Sin lock");
        membershipLock[msg.sender].active = false;
        _transfer(address(this), msg.sender, l.amount);
        emit MembershipUnlocked(msg.sender, l.amount);
    }

    function hasMembership(address u) public view returns (bool) {
        bool prepaid = membershipUntil[u] >= block.timestamp;
        bool locked = membershipLock[u].active && membershipLock[u].amount >= minStakeForAccess;
        return prepaid || locked;
    }
    
    function activateMembershipByVoucher(
        address user,
        uint256 daysPaid,
        uint256 nonce,
        uint256 deadline,
        bytes calldata sig
    ) external nonReentrant whenNotPaused {
        require(block.timestamp <= deadline, "Voucher expirado");
        require(nonce == nonces[user]++, "Nonce invalido");
        require(daysPaid > 0 && daysPaid <= 365, "Rango invalido");
        
        bytes32 structHash = keccak256(abi.encode(
            MEMBERSHIP_TYPEHASH,
            user,
            daysPaid,
            nonce,
            deadline
        ));
        bytes32 digest = ECDSA.toTypedDataHash(DOMAIN_SEPARATOR, structHash);
        address recovered = ECDSA.recover(digest, sig);
        require(recovered == voucherSigner, "Firma invalida");
        
        uint256 base = membershipUntil[user] > block.timestamp ? membershipUntil[user] : block.timestamp;
        membershipUntil[user] = base + daysPaid * 1 days;
        emit MembershipActivatedByVoucher(user, daysPaid, nonce, deadline);
    }

    // =========================
    //       ADMIN
    // =========================
    function setPSYKooDnline() external onlyOwner {
        require(!cicudOnline, "Ya online");
        cicudOnline = true;
        emit PSYKooDOnline();
    }
    
    function setInactivityPeriod(uint256 seconds_) external onlyOwner {
        require(seconds_ >= 1 days && seconds_ <= 90 days, "Fuera de rango");
        inactivityPeriod = seconds_;
        emit InactivityPeriodUpdated(seconds_);
    }

    function setTreasury(address t) external onlyOwner {
        require(t != address(0), "addr zero");
        treasury = t;
        emit TreasuryUpdated(t);
    }

    function setVoucherSigner(address s) external onlyOwner {
        require(s != address(0), "addr zero");
        voucherSigner = s;
        emit VoucherSignerUpdated(s);
    }

    function setParams(
        uint256 _pricePer90DaysZKS,
        uint256 _minStakeForAccess,
        uint256 _minHoldForConsume
    ) external onlyOwner {
        require(_pricePer90DaysZKS > 0, "precio 0");
        pricePer90DaysZKS = _pricePer90DaysZKS;
        minStakeForAccess = _minStakeForAccess;
        minHoldForConsume = _minHoldForConsume;
        emit ParamsUpdated(_pricePer90DaysZKS, _minStakeForAccess, _minHoldForConsume);
    }

    function setAutorVault(address _autorVault) external onlyOwner {
        require(_autorVault != address(0), "addr zero");
        autorVault = _autorVault;
        emit AutorVaultUpdated(_autorVault);
    }

    function rescueTokens(address token, address to, uint256 amount) external onlyOwner {
        require(token != address(this), "No rescatar ZKS");
        require(to != address(0), "addr zero");
        IERC20(token).transfer(to, amount);
    }

    // =========================
    //   LECTURAS AUX
    // =========================
    function poolsLiberadosEnLoteActual() external view returns (uint256) {
        uint256 completados = poolActual == 0 ? 0 : (poolActual % POOLS_PER_LOTE);
        return completados == 0 ? (poolActual == 0 ? 0 : POOLS_PER_LOTE) : completados;
    }

    function poolsRestantesEnLoteActual() external view returns (uint256) {
        uint256 pl = poolActual % POOLS_PER_LOTE;
        return pl == 0 ? POOLS_PER_LOTE : (POOLS_PER_LOTE - pl);
    }

    function lotesRestantes() external view returns (uint256) {
        return MAX_LOTES - lotesLiberados;
    }
}
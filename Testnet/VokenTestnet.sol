// SPDX-License-Identifier: MIT
// @custom:security-contact: development@vfund.io

pragma solidity ^0.8.4;

/** Tokenomics
 * Redistribution (RFI)     4% - auto distribute to all Voken holders
 * Fund                     5% - used to increase the total fund value
 * Liquidity                4% - auto add to the locked liquidity pool
 * R&D                      2% - used for marketing and research
 * AntiWhale measures:
 *  - max tx: 1% of total Voken supply
 *  - max account bal: 4% of total Voken supply
 */

import "./VokenImports.sol";

abstract contract Tokenomics {
    using SafeMath for uint256;

    // --------------------- Token Settings ------------------- //

    string internal constant NAME = "Voken-Testnet"; // Voken Testnet
    string internal constant SYMBOL = "VKN-T";

    uint16 internal constant FEES_DIVISOR = 20**3;
    uint8 internal constant DECIMALS = 18;

    uint256 private constant MAX = ~uint256(0);
    uint256 internal constant TOTAL_SUPPLY = 20_000_000 * 10**DECIMALS;
    uint256 internal _reflectedSupply = (MAX - (MAX % TOTAL_SUPPLY));

    uint256 internal constant maxTransactionAmount = TOTAL_SUPPLY / 100; // 1% of the total supply
    uint256 internal constant maxWalletBalance = TOTAL_SUPPLY / 25; // 4% of the total supply
    uint256 internal constant thresholdSwapToLiquidity = TOTAL_SUPPLY / 1_000; // 0.01% of the total supply (2.000 vokens)

    // --------------------- Fees Settings ------------------- //
    address internal rndAddress = 0xd12dE5802BF43204418C068c0c9013FF459EA47a;
    address internal fundAddress = 0xf12f4A1589C6A1a1aC96678A76C62CFF60c2C6B8;
    address internal definitiveBurnAddress = 0x000000000000000000000000000000000000dEaD;

    enum FeeType {
        Liquidity,
        Rfi,
        External
    }

    struct Fee {
        FeeType name;
        uint256 value;
        address recipient;
        uint256 total;
    }

    Fee[] internal fees;
    uint256 internal sumOfFees;

    constructor() {
        _addFees();
    }

    function _addFee(
        FeeType name,
        uint256 value,
        address recipient
    ) private {
        fees.push(Fee(name, value, recipient, 0));
        sumOfFees += value;
    }

    function _addFees() private {
        _addFee(FeeType.Rfi, 40, address(this));
        _addFee(FeeType.External, 50, fundAddress);
        _addFee(FeeType.Liquidity, 40, address(this));
        _addFee(FeeType.External, 20, rndAddress);
    }

    function _getFeesCount() internal view returns (uint256) {
        return fees.length;
    }

    function _getFeeStruct(uint256 index) private view returns (Fee storage) {
        require(index >= 0 && index < fees.length, "Fee index out of bounds");
        return fees[index];
    }

    function getFee(uint256 index)
        public
        view
        returns (
            FeeType,
            uint256,
            address,
            uint256
        )
    {
        Fee memory fee = _getFeeStruct(index);
        return (fee.name, fee.value, fee.recipient, fee.total);
    }

    function _addFeeCollectedAmount(uint256 index, uint256 amount) internal {
        Fee storage fee = _getFeeStruct(index);
        fee.total = fee.total.add(amount);
    }

    function getCollectedFeeTotal(uint256 index)
        external
        view
        returns (uint256)
    {
        Fee memory fee = _getFeeStruct(index);
        return fee.total;
    }
}

abstract contract Presaleable is Manageable {
    bool internal isInPresale;

    function setPreseableEnabled(bool value) external onlyManager {
        isInPresale = value;
    }
}

abstract contract BaseRfiToken is
    IERC20,
    IERC20Metadata,
    Ownable,
    Presaleable,
    Tokenomics
{
    using SafeMath for uint256;
    using Address for address;

    mapping(address => uint256) internal _reflectedBalances;
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;

    mapping(address => bool) internal _isExcludedFromFee;
    mapping(address => bool) internal _isExcludedFromRewards;

    address[] private _excluded;

    constructor() {
        _reflectedBalances[owner()] = _reflectedSupply;

        _isExcludedFromFee[owner()] = true;
        _isExcludedFromFee[rndAddress] = true;
        _isExcludedFromFee[fundAddress] = true;
        _isExcludedFromFee[address(this)] = true;

        _exclude(address(this)); 
        _exclude(definitiveBurnAddress);

        emit Transfer(address(0), owner(), TOTAL_SUPPLY);
    }

    /** Functions required by IERC20Metadat **/
    function name() external pure override returns (string memory) {
        return NAME;
    }

    function symbol() external pure override returns (string memory) {
        return SYMBOL;
    }

    function decimals() external pure override returns (uint8) {
        return DECIMALS;
    }

    /** Functions required by IERC20Metadat - END **/

    /** Functions required by IERC20 **/
    function totalSupply() external pure override returns (uint256) {
        return TOTAL_SUPPLY;
    }

    function balanceOf(address account) public view override returns (uint256) {
        if (_isExcludedFromRewards[account]) return _balances[account];
        return tokenFromReflection(_reflectedBalances[account]);
    }

    function transfer(address recipient, uint256 amount)
        external
        override
        returns (bool)
    {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender)
        external
        view
        override
        returns (uint256)
    {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount)
        external
        override
        returns (bool)
    {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(
            sender,
            _msgSender(),
            _allowances[sender][_msgSender()].sub(
                amount,
                "ERC20: transfer amount exceeds allowance"
            )
        );
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue)
        public
        virtual
        returns (bool)
    {
        _approve(
            _msgSender(),
            spender,
            _allowances[_msgSender()][spender].add(addedValue)
        );
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue)
        public
        virtual
        returns (bool)
    {
        _approve(
            _msgSender(),
            spender,
            _allowances[_msgSender()][spender].sub(
                subtractedValue,
                "ERC20: decreased allowance below zero"
            )
        );
        return true;
    }

    function isExcludedFromReward(address account)
        external
        view
        returns (bool)
    {
        return _isExcludedFromRewards[account];
    }

    function reflectionFromToken(uint256 tAmount, bool deductTransferFee)
        external
        view
        returns (uint256)
    {
        require(tAmount <= TOTAL_SUPPLY, "Amount must be less than supply");
        if (!deductTransferFee) {
            (uint256 rAmount, , , , ) = _getValues(tAmount, 0);
            return rAmount;
        } else {
            (, uint256 rTransferAmount, , , ) = _getValues(
                tAmount,
                _getSumOfFees(_msgSender(), tAmount)
            );
            return rTransferAmount;
        }
    }

    function tokenFromReflection(uint256 rAmount)
        internal
        view
        returns (uint256)
    {
        require(
            rAmount <= _reflectedSupply,
            "Amount must be less than total reflections"
        );
        uint256 currentRate = _getCurrentRate();
        return rAmount.div(currentRate);
    }

    function excludeFromReward(address account) external onlyOwner {
        require(!_isExcludedFromRewards[account], "Account is not included");
        _exclude(account);
    }

    function _exclude(address account) internal {
        if (_reflectedBalances[account] > 0) {
            _balances[account] = tokenFromReflection(
                _reflectedBalances[account]
            );
        }
        _isExcludedFromRewards[account] = true;
        _excluded.push(account);
    }

    function includeInReward(address account) external onlyOwner {
        require(_isExcludedFromRewards[account], "Account is not excluded");
        for (uint256 i = 0; i < _excluded.length; i++) {
            if (_excluded[i] == account) {
                _excluded[i] = _excluded[_excluded.length - 1];
                _balances[account] = 0;
                _isExcludedFromRewards[account] = false;
                _excluded.pop();
                break;
            }
        }
    }

    function setExcludedFromFee(address account, bool value)
        external
        onlyOwner
    {
        _isExcludedFromFee[account] = value;
    }

    function isExcludedFromFee(address account) public view returns (bool) {
        return _isExcludedFromFee[account];
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal {
        require(
            owner != address(0),
            "BaseRfiToken: approve from the zero address"
        );
        require(
            spender != address(0),
            "BaseRfiToken: approve to the zero address"
        );

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _isUnlimitedSender(address account) internal view returns (bool) {
        return (account == owner());
    }

    function _isUnlimitedRecipient(address account)
        internal
        view
        returns (bool)
    {
        return (account == owner() ||
            account == fundAddress ||
            account == rndAddress ||
            account == definitiveBurnAddress);
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) private {
        require(
            sender != address(0),
            "BaseRfiToken: transfer from the zero address"
        );
        require(
            recipient != address(0),
            "BaseRfiToken: transfer to the zero address"
        );
        require(
            sender != address(fundAddress),
            "BaseRfiToken: transfer from the fund address"
        );
        require(amount > 0, "Transfer amount must be greater than zero");

        bool takeFee = true;

        if (isInPresale) {
            takeFee = false;
        } else {
            if (
                amount > maxTransactionAmount &&
                !_isUnlimitedSender(sender) &&
                !_isUnlimitedRecipient(recipient)
            ) {
                revert("Transfer amount exceeds the maxTxAmount.");
            }

            if (
                maxWalletBalance > 0 &&
                !_isUnlimitedSender(sender) &&
                !_isUnlimitedRecipient(recipient) &&
                !_isV2Pair(recipient)
            ) {
                uint256 recipientBalance = balanceOf(recipient);
                require(
                    recipientBalance + amount <= maxWalletBalance,
                    "New balance would exceed the maxWalletBalance"
                );
            }
        }

        if (_isExcludedFromFee[sender] || _isExcludedFromFee[recipient]) {
            takeFee = false;
        }

        _beforeTokenTransfer(sender, recipient, amount, takeFee);
        _transferTokens(sender, recipient, amount, takeFee);
    }

    function _transferTokens(
        address sender,
        address recipient,
        uint256 amount,
        bool takeFee
    ) private {
        uint256 sumOfFees = _getSumOfFees(sender, amount);
        if (!takeFee) {
            sumOfFees = 0;
        }
        (
            uint256 rAmount,
            uint256 rTransferAmount,
            uint256 tAmount,
            uint256 tTransferAmount,
            uint256 currentRate
        ) = _getValues(amount, sumOfFees);


        _reflectedBalances[sender] = _reflectedBalances[sender].sub(rAmount);
        _reflectedBalances[recipient] = _reflectedBalances[recipient].add(
            rTransferAmount
        );

        if (_isExcludedFromRewards[sender]) {
            _balances[sender] = _balances[sender].sub(tAmount);
        }
        if (_isExcludedFromRewards[recipient]) {
            _balances[recipient] = _balances[recipient].add(tTransferAmount);
        }

        _takeFees(amount, currentRate, sumOfFees);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _takeFees(
        uint256 amount,
        uint256 currentRate,
        uint256 sumOfFees
    ) private {
        if (sumOfFees > 0 && !isInPresale) {
            _takeTransactionFees(amount, currentRate);
        }
    }

    function _getValues(uint256 tAmount, uint256 feesSum)
        internal
        view
        returns (
            uint256,
            uint256,
            uint256,
            uint256,
            uint256
        )
    {
        uint256 tTotalFees = tAmount.mul(feesSum).div(FEES_DIVISOR);
        uint256 tTransferAmount = tAmount.sub(tTotalFees);
        uint256 currentRate = _getCurrentRate();
        uint256 rAmount = tAmount.mul(currentRate);
        uint256 rTotalFees = tTotalFees.mul(currentRate);
        uint256 rTransferAmount = rAmount.sub(rTotalFees);

        return (
            rAmount,
            rTransferAmount,
            tAmount,
            tTransferAmount,
            currentRate
        );
    }

    function _getCurrentRate() internal view returns (uint256) {
        (uint256 rSupply, uint256 tSupply) = _getCurrentSupply();
        return rSupply.div(tSupply);
    }

    function _getCurrentSupply() internal view returns (uint256, uint256) {
        uint256 rSupply = _reflectedSupply;
        uint256 tSupply = TOTAL_SUPPLY;

        for (uint256 i = 0; i < _excluded.length; i++) {
            if (
                _reflectedBalances[_excluded[i]] > rSupply ||
                _balances[_excluded[i]] > tSupply
            ) return (_reflectedSupply, TOTAL_SUPPLY);
            rSupply = rSupply.sub(_reflectedBalances[_excluded[i]]);
            tSupply = tSupply.sub(_balances[_excluded[i]]);
        }
        if (tSupply == 0 || rSupply < _reflectedSupply.div(TOTAL_SUPPLY))
            return (_reflectedSupply, TOTAL_SUPPLY);
        return (rSupply, tSupply);
    }

    function _beforeTokenTransfer(
        address sender,
        address recipient,
        uint256 amount,
        bool takeFee
    ) internal virtual;

    function _getSumOfFees(address sender, uint256 amount)
        internal
        view
        virtual
        returns (uint256);

    function _isV2Pair(address account) internal view virtual returns (bool);

    function _redistribute(
        uint256 amount,
        uint256 currentRate,
        uint256 fee,
        uint256 index
    ) internal {
        uint256 tFee = amount.mul(fee).div(FEES_DIVISOR);
        uint256 rFee = tFee.mul(currentRate);

        _reflectedSupply = _reflectedSupply.sub(rFee);
        _addFeeCollectedAmount(index, tFee);
    }

    function _takeTransactionFees(uint256 amount, uint256 currentRate)
        internal
        virtual;
}

abstract contract Liquifier is Ownable, Manageable {
    using SafeMath for uint256;

    uint256 private withdrawableBalance;

    enum Env {
        Testnet,
        MainnetV1,
        MainnetV2
    }
    Env private _env;

    // will be implemented in official release
    address private multiSigWallet = 0x42489c73E040fF7a3dA77294A54fA0a617550072;

    // PancakeSwap Testnet = https://pancake.kiemtienonline360.com/
    address private _testnetRouterAddress =
        0x9Ac64Cc6e4415144C455BD8E4837Fea55603e5c3;

    IPancakeV2Router internal _router;
    address internal _pair;

    bool private inSwapAndLiquify;
    bool private swapAndLiquifyEnabled = true;

    uint256 private maxTransactionAmount;
    uint256 private thresholdSwapToLiquidity;

    modifier lockTheSwap() {
        inSwapAndLiquify = true;
        _;
        inSwapAndLiquify = false;
    }

    event RouterSet(address indexed router);
    event SwapAndLiquify(
        uint256 tokensSwapped,
        uint256 ethReceived,
        uint256 tokensIntoLiquidity
    );
    event SwapAndLiquifyEnabledUpdated(bool enabled);
    event LiquidityAdded(
        uint256 tokenAmountSent,
        uint256 ethAmountSent,
        uint256 liquidity
    );

    receive() external payable {}

    function initializeLiquiditySwapper(
        Env env,
        uint256 maxTx,
        uint256 liquifyAmount
    ) internal {
        _env = env;
        _setRouterAddress(_testnetRouterAddress);

        maxTransactionAmount = maxTx;
        thresholdSwapToLiquidity = liquifyAmount;
    }


    function liquify(uint256 contractTokenBalance, address sender) internal {
        if (contractTokenBalance >= maxTransactionAmount)
            contractTokenBalance = maxTransactionAmount;

        bool isOverRequiredTokenBalance = (contractTokenBalance >=
            thresholdSwapToLiquidity);

        if (
            isOverRequiredTokenBalance &&
            swapAndLiquifyEnabled &&
            !inSwapAndLiquify &&
            (sender != _pair)
        ) {
            _swapAndLiquify(contractTokenBalance);
        }
    }

    function _setRouterAddress(address router) private {
        IPancakeV2Router _newPancakeRouter = IPancakeV2Router(router);
        _pair = IPancakeV2Factory(_newPancakeRouter.factory()).createPair(
            address(this),
            _newPancakeRouter.WETH()
        );
        _router = _newPancakeRouter;
        emit RouterSet(router);
    }

    function _swapAndLiquify(uint256 amount) private lockTheSwap {
        uint256 half = amount.div(2);
        uint256 otherHalf = amount.sub(half);

        uint256 initialBalance = address(this).balance;

        _swapTokensForEth(half);

        uint256 newBalance = address(this).balance.sub(initialBalance);

        _addLiquidity(otherHalf, newBalance);

        emit SwapAndLiquify(half, newBalance, otherHalf);
    }

    function _swapTokensForEth(uint256 tokenAmount) private {
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = _router.WETH();

        _approveDelegate(address(this), address(_router), tokenAmount);

        _router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokenAmount,
            0,
            path,
            address(this),
            block.timestamp
        );
    }

    function _addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
        _approveDelegate(address(this), address(_router), tokenAmount);

        (uint256 tokenAmountSent, uint256 ethAmountSent, uint256 liquidity) = _router
            .addLiquidityETH{value: ethAmount}(
            address(this),
            tokenAmount,
            0,
            0,
            owner(),
            block.timestamp
        );

        withdrawableBalance = address(this).balance;
        emit LiquidityAdded(tokenAmountSent, ethAmountSent, liquidity);
    }

    function setRouterAddress(address router) external onlyManager {
        _setRouterAddress(router);
    }

    function setSwapAndLiquifyEnabled(bool enabled) external onlyManager {
        swapAndLiquifyEnabled = enabled;
        emit SwapAndLiquifyEnabledUpdated(swapAndLiquifyEnabled);
    }

    function withdrawLockedBNB(address payable recipient) external onlyManager {
        require(
            recipient != address(0),
            "Cannot withdraw the BNB balance to the zero address"
        );
        require(
            withdrawableBalance > 0,
            "The BNB balance must be greater than 0"
        );

        uint256 amount = withdrawableBalance;
        withdrawableBalance = 0;
        recipient.transfer(amount);
    }


    function _approveDelegate(
        address owner,
        address spender,
        uint256 amount
    ) internal virtual;
}

abstract contract Voken is BaseRfiToken, Liquifier {
    using SafeMath for uint256;

    constructor(Env _env) {
        initializeLiquiditySwapper(
            _env,
            maxTransactionAmount,
            thresholdSwapToLiquidity
        );

        _exclude(_pair);
    }

    function _isV2Pair(address account) internal view override returns (bool) {
        return (account == _pair);
    }

    function _getSumOfFees(address sender, uint256 amount)
        internal
        view
        override
        returns (uint256)
    {
        return sumOfFees;
    }

    function _beforeTokenTransfer(
        address sender,
        address,
        uint256,
        bool
    ) internal override {
        if (!isInPresale) {
            uint256 contractTokenBalance = balanceOf(address(this));
            liquify(contractTokenBalance, sender);
        }
    }

    function _takeTransactionFees(uint256 amount, uint256 currentRate)
        internal
        override
    {
        if (isInPresale) {
            return;
        }

        uint256 feesCount = _getFeesCount();
        for (uint256 index = 0; index < feesCount; index++) {
            (FeeType name, uint256 value, address recipient, ) = getFee(index);
            if (value == 0) continue;

            if (name == FeeType.Rfi) {
                _redistribute(amount, currentRate, value, index);
            } else {
                _takeFee(amount, currentRate, value, recipient, index);
            }
        }
    }

    function _takeFee(
        uint256 amount,
        uint256 currentRate,
        uint256 fee,
        address recipient,
        uint256 index
    ) private {
        uint256 tAmount = amount.mul(fee).div(FEES_DIVISOR);
        uint256 rAmount = tAmount.mul(currentRate);

        _reflectedBalances[recipient] = _reflectedBalances[recipient].add(
            rAmount
        );
        if (_isExcludedFromRewards[recipient])
            _balances[recipient] = _balances[recipient].add(tAmount);

        _addFeeCollectedAmount(index, tAmount);
    }

    function _approveDelegate(
        address owner,
        address spender,
        uint256 amount
    ) internal override {
        _approve(owner, spender, amount);
    }
}

contract VokenTestnet is Voken {
    constructor() Voken(Env.Testnet) {
        _approve(owner(), address(_router), ~uint256(0));
    }
}
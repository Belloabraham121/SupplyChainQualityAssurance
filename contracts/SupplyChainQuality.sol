// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// @title A supply chain quality control smart contract
/// @notice This contract manages product registration, quality checks, and role-based access control for a supply chain
/// @dev Inherits OpenZeppelin's AccessControl for role management
contract SupplyChainQuality is AccessControl {
    bytes32 public constant MANUFACTURER_ROLE = keccak256("MANUFACTURER_ROLE");
    bytes32 public constant DISTRIBUTOR_ROLE = keccak256("DISTRIBUTOR_ROLE");
    bytes32 public constant RETAILER_ROLE = keccak256("RETAILER_ROLE");

    uint256 private _productIdCounter;

    struct Product {
        uint256 id;
        string name;
        address manufacturer;
        uint256 manufactureDate;
        string originLocation;
        bool isCompleted;
        string batchNumber;
        uint256 expirationDate;
    }

    struct QualityCheck {
        address inspector;
        uint256 timestamp;
        string checkpointName;
        bool passed;
        string notes;
    }

    mapping(uint256 => Product) public products;
    mapping(uint256 => QualityCheck[]) public qualityChecks;

    event ProductRegistered(uint256 indexed productId, string name, address manufacturer);
    event QualityCheckPerformed(uint256 indexed productId, string checkpointName, bool passed);
    event ProductCompleted(uint256 indexed productId);
    event ProductUpdated(uint256 indexed productId);

    /// @notice Initializes the contract and grants the deployer the admin role
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Registers a new product in the supply chain
    /// @dev Only callable by addresses with the MANUFACTURER_ROLE
    /// @param _name The name of the product
    /// @param _originLocation The origin location of the product
    /// @param _batchNumber The batch number of the product
    /// @param _expirationDate The expiration date of the product
    function registerProduct(
        string memory _name, 
        string memory _originLocation, 
        string memory _batchNumber, 
        uint256 _expirationDate
    ) public onlyRole(MANUFACTURER_ROLE) {
        _productIdCounter++;
        uint256 newProductId = _productIdCounter;

        products[newProductId] = Product({
            id: newProductId,
            name: _name,
            manufacturer: msg.sender,
            manufactureDate: block.timestamp,
            originLocation: _originLocation,
            isCompleted: false,
            batchNumber: _batchNumber,
            expirationDate: _expirationDate
        });

        emit ProductRegistered(newProductId, _name, msg.sender);
    }

    /// @notice Performs a quality check on a product
    /// @dev Callable by addresses with MANUFACTURER_ROLE, DISTRIBUTOR_ROLE, or RETAILER_ROLE
    /// @param _productId The ID of the product being checked
    /// @param _checkpointName The name of the checkpoint where the check is performed
    /// @param _passed Whether the product passed the quality check
    /// @param _notes Additional notes about the quality check
    function performQualityCheck(uint256 _productId, string memory _checkpointName, bool _passed, string memory _notes) public {
        require(hasRole(MANUFACTURER_ROLE, msg.sender) || hasRole(DISTRIBUTOR_ROLE, msg.sender) || hasRole(RETAILER_ROLE, msg.sender), "Caller is not authorized");
        require(!products[_productId].isCompleted, "Product journey already completed");

        QualityCheck memory newCheck = QualityCheck({
            inspector: msg.sender,
            timestamp: block.timestamp,
            checkpointName: _checkpointName,
            passed: _passed,
            notes: _notes
        });

        qualityChecks[_productId].push(newCheck);

        emit QualityCheckPerformed(_productId, _checkpointName, _passed);
    }

    /// @notice Marks a product's journey as completed
    /// @dev Only callable by addresses with the RETAILER_ROLE
    /// @param _productId The ID of the product to be marked as completed
    function completeProductJourney(uint256 _productId) public onlyRole(RETAILER_ROLE) {
        require(!products[_productId].isCompleted, "Product journey already completed");

        products[_productId].isCompleted = true;

        emit ProductCompleted(_productId);
    }

    /// @notice Retrieves the details of a specific product
    /// @param _productId The ID of the product to retrieve
    /// @return Product struct containing the product details
    function getProductDetails(uint256 _productId) public view returns (Product memory) {
        return products[_productId];
    }

    /// @notice Retrieves all quality checks for a specific product
    /// @param _productId The ID of the product to retrieve quality checks for
    /// @return An array of QualityCheck structs
    function getQualityChecks(uint256 _productId) public view returns (QualityCheck[] memory) {
        return qualityChecks[_productId];
    }

    /// @notice Updates the information of an existing product
    /// @dev Only callable by the original manufacturer of the product
    /// @param _productId The ID of the product to update
    /// @param _newName The new name of the product
    /// @param _newOriginLocation The new origin location of the product
    /// @param _newBatchNumber The new batch number of the product
    /// @param _newExpirationDate The new expiration date of the product
    function updateProductInfo(
        uint256 _productId, 
        string memory _newName, 
        string memory _newOriginLocation, 
        string memory _newBatchNumber, 
        uint256 _newExpirationDate
    ) public onlyRole(MANUFACTURER_ROLE) {
        require(products[_productId].manufacturer == msg.sender, "Only the original manufacturer can update the product");
        require(!products[_productId].isCompleted, "Cannot update completed products");

        Product storage product = products[_productId];
        product.name = _newName;
        product.originLocation = _newOriginLocation;
        product.batchNumber = _newBatchNumber;
        product.expirationDate = _newExpirationDate;

        emit ProductUpdated(_productId);
    }

    /// @notice Grants the MANUFACTURER_ROLE to an account
    /// @dev Only callable by the contract admin
    /// @param account The address to grant the role to
    function grantManufacturerRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(MANUFACTURER_ROLE, account);
        emit RoleGranted(MANUFACTURER_ROLE, account, msg.sender);
    }

    /// @notice Grants the DISTRIBUTOR_ROLE to an account
    /// @dev Only callable by the contract admin
    /// @param account The address to grant the role to
    function grantDistributorRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(DISTRIBUTOR_ROLE, account);
        emit RoleGranted(DISTRIBUTOR_ROLE, account, msg.sender);
    }

    /// @notice Grants the RETAILER_ROLE to an account
    /// @dev Only callable by the contract admin
    /// @param account The address to grant the role to
    function grantRetailerRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(RETAILER_ROLE, account);
        emit RoleGranted(RETAILER_ROLE, account, msg.sender);
    }

    /// @notice Revokes the MANUFACTURER_ROLE from an account
    /// @dev Only callable by the contract admin
    /// @param account The address to revoke the role from
    function revokeManufacturerRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(MANUFACTURER_ROLE, account);
        emit RoleRevoked(MANUFACTURER_ROLE, account, msg.sender);
    }

    /// @notice Revokes the DISTRIBUTOR_ROLE from an account
    /// @dev Only callable by the contract admin
    /// @param account The address to revoke the role from
    function revokeDistributorRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(DISTRIBUTOR_ROLE, account);
        emit RoleRevoked(DISTRIBUTOR_ROLE, account, msg.sender);
    }

    /// @notice Revokes the RETAILER_ROLE from an account
    /// @dev Only callable by the contract admin
    /// @param account The address to revoke the role from
    function revokeRetailerRole(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(RETAILER_ROLE, account);
        emit RoleRevoked(RETAILER_ROLE, account, msg.sender);
    }
}
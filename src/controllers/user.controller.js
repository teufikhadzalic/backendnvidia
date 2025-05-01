const bcrypt = require("bcrypt.js");
const userRepository = require("../repositories/user.repository.js");
const baseResponse = require("../utils/baseResponse.util");
const jwt = require("jsonwebtoken");

// Regex untuk validasi email dan password
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

// Register user
exports.registerUser = async (req, res) => {
    const { name, email, password, balance } = req.body;

    if (!emailRegex.test(email)) {
        return baseResponse(res, false, 400, "Invalid email format");
    }
    if (!passwordRegex.test(password)) {
        return baseResponse(res, false, 400, "Password must be at least 8 characters, contain uppercase, lowercase, number, and special character");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await userRepository.registerUser({
            name,
            email,
            password: hashedPassword,
            balance,
        });
        console.log(`User registered: ${user.email}`); // Log di terminal
        return baseResponse(res, true, 201, "User registered successfully", user);
    } catch (error) {
        return baseResponse(res, false, 500, error.message || "Server Error");
    }
};

// Get user by email
exports.getUserByEmail = async (req, res) => {
    try {
        const { email } = req.params;
        const user = await userRepository.getUserByEmail(email);

        if (!user) {
            return baseResponse(res, false, 404, "User not found");
        }

        return baseResponse(res, true, 200, "User found", user);
    } catch (error) {
        return baseResponse(res, false, 500, "Error retrieving user", error);
    }
};

// Update user
exports.updateUser = async (req, res) => {
    try {
        const { name, email, password, balance } = req.body;

        // Validasi input
        if (!email || !name) {
            return baseResponse(res, false, 400, "Email and name are required");
        }
        if (!emailRegex.test(email)) {
            return baseResponse(res, false, 400, "Invalid email format");
        }

        let hashedPassword = null;
        if (password) {
            if (!passwordRegex.test(password)) {
                return baseResponse(res, false, 400, "Password must be at least 8 characters, contain uppercase, lowercase, number, and special character");
            }
            hashedPassword = await bcrypt.hash(password, 10);
        }

        // Update user di database
        const updatedUser = await userRepository.updateUser({
            name,
            email,
            password: hashedPassword,
            balance,
        });

        if (!updatedUser) {
            return baseResponse(res, false, 404, "User not found");
        }

        return baseResponse(res, true, 200, "User updated successfully", updatedUser);
    } catch (error) {
        return baseResponse(res, false, 500, error.message || "Error updating user");
    }
};
// Delete user
exports.deleteUser = async (req, res) => {
    try {
        const { id } = req.params;
        const deletedUser = await userRepository.deleteUser(id);

        if (!deletedUser) {
            return baseResponse(res, false, 404, "User not found");
        }

        return baseResponse(res, true, 200, "User deleted successfully", deletedUser);
    } catch (error) {
        return baseResponse(res, false, 500, "Error deleting user", error);
    }
};

// Login user (compare password hash)
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        console.log("Login request received:", { email, password });

        const user = await userRepository.getUserByEmail(email);
        if (!user) {
            console.log("User not found:", email);
            return baseResponse(res, false, 404, "User not found");
        }

        console.log("User found:", user);

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log("Invalid password for user:", email);
            return baseResponse(res, false, 400, "Invalid password");
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log("Token generated for user:", email);
        return baseResponse(res, true, 200, "Login successful", { token, user });
    } catch (error) {
        console.error("Error in loginUser:", error);
        return baseResponse(res, false, 500, "Error logging in", error);
    }
};

//top up
exports.topUpUser = async (req, res) => {
    try {
        const { user_id, amount } = req.body;

        // Validasi input
        if (!user_id || !amount || amount <= 0) {
            return baseResponse(res, false, 400, "User ID and valid amount are required");
        }

        const updatedUser = await userRepository.topUpUser(user_id, amount);

        if (!updatedUser) {
            return baseResponse(res, false, 404, "User not found");
        }

        return baseResponse(res, true, 200, "Top-up successful", updatedUser);
    } catch (error) {
        return baseResponse(res, false, 500, error.message || "Server Error");
    }
};

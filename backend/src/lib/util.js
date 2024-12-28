import jwt from "jsonwebtoken";

export const generateToken = (userId, res) => {
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, {expiresIn: "7d",});

    res.cookie("jwt", token, {
        maxAge: 7 * 24 * 60 * 60 * 1000, //converted 7days into milliseconds.
        httpOnly: true, //prevent XSS attacks
        sameSite: "strict", //CSRF attacks prevention
        secure: process.env.NODE_ENV !== "development",
    });

    return token;
}
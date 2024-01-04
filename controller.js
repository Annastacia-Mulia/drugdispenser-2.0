import bcryptjs from 'bcryptjs';
import { createHash } from 'crypto';
import { validationResult, matchedData } from 'express-validator';
import { generateToken, verifyToken } from './tokenHandler.js';
import DB from './dbcon.js';

const validation_result = validationResult.withDefaults({
    formatter: (error) => error.msg,
});

export const validate = (req, res, next) => {
    const errors = validation_result(req).mapped();
    if (Object.keys(errors).length) {
        return res.status(422).json({
            status: 422,
            errors,
        });
    }
    next();
};

// If email already exists in database
export const fetchUserByEmailOrID = async (data, isEmail = true) => {
    let sql = 'SELECT * FROM `users` WHERE `email`=?';
    if (!isEmail)
        sql = 'SELECT `id` ,`name`, `email` FROM `users` WHERE `id`=?';
    const [row] = await DB.execute(sql, [data]);
    return row;
};

/*export default {
    register: async (req, res, next) => {
        try {
            const { name, email, password } = matchedData(req);

            const saltRounds = 10;
            // Hash the password
            const hashPassword = await bcryptjs.hash(password, saltRounds);

            // Store user data in the database
            const [result] = await DB.execute(
                'INSERT INTO `users` (`name`,`email`,`password`) VALUES (?,?,?)',
                [name, email, hashPassword]
            );
            res.status(201).json({
                status: 201,
                message: 'You have been successfully registered.',
                user_id: result.insertId,
            });
        } catch (err) {
            next(err);
        }
    },

    signin: async (req, res, next) => {
        try {
            const { user, password } = req.body;
            const verifyPassword = await bcryptjs.compare(
                password,
                user.password
            );
            if (!verifyPassword) {
                return res.status(422).json({
                    status: 422,
                    message: 'Incorrect password!',
                });
            }

            // Generating Access and Refresh Token
            const access_token = generateToken({ id: user.id });
            const refresh_token = generateToken({ id: user.id }, false);

            const md5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            // Storing refresh token in MD5 format
            const [result] = await DB.execute(
                'INSERT INTO `refresh_tokens` (`user_id`,`token`) VALUES (?,?)',
                [user.id, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Failed to whitelist the refresh token.');
            }
            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },

    getUser: async (req, res, next) => {
        try {
            // Verify the access token
            const data = verifyToken(req.headers.access_token);
            if (data?.status) return res.status(data.status).json(data);
            // fetching user by the `id` (column)
            const user = await fetchUserByEmailOrID(data.id, false);
            if (user.length !== 1) {
                return res.status(404).json({
                    status: 404,
                    message: 'User not found',
                });
            }
            res.json({
                status: 200,
                user: user[0],
            });
        } catch (err) {
            next(err);
        }
    },

    refreshToken: async (req, res, next) => {
        try {
            const refreshToken = req.headers.refresh_token;
            // Verify the refresh token
            const data = verifyToken(refreshToken, false);
            if (data?.status) return res.status(data.status).json(data);

            // Converting refresh token to md5 format
            const md5Refresh = createHash('md5')
                .update(refreshToken)
                .digest('hex');

            // Finding the refresh token in the database
            const [refTokenRow] = await DB.execute(
                'SELECT * from `refresh_tokens` WHERE token=?',
                [md5Refresh]
            );

            if (refTokenRow.length !== 1) {
                return res.json({
                    status: 401,
                    message: 'Unauthorized: Invalid Refresh Token.',
                });
            }




            

            // Generating new access and refresh token
            const access_token = generateToken({ id: data.id });
            const refresh_token = generateToken({ id: data.id }, false);

            const newMd5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            // Replacing the old refresh token to new refresh token
            const [result] = await DB.execute(
                'UPDATE `refresh_tokens` SET `token`=? WHERE `token`=?',
                [newMd5Refresh, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Failed to whitelist the Refresh token.');
            }

            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },
};*/
// ... (import statements remain the same)

export default {
    register: async (req, res, next) => {
        try {
            const { name, email, password } = matchedData(req);

            const saltRounds = 10;
            // Hash the password
            const hashPassword = await bcryptjs.hash(password, saltRounds);

            // Store user data in the database
            const [result] = await DB.execute(
                'INSERT INTO `users` (`name`,`email`,`password`) VALUES (?,?,?)',
                [name, email, hashPassword]
            );
            res.status(201).json({
                status: 201,
                message: 'You have been successfully registered.',
                user_id: result.insertId,
            });
        } catch (err) {
            next(err);
        }
    },

    signin: async (req, res, next) => {
        try {
            const { user, password } = req.body;
            const verifyPassword = await bcryptjs.compare(
                password,
                user.password
            );
            if (!verifyPassword) {
                return res.status(401).json({
                    status: 401,
                    message: 'Incorrect password!',
                });
            }

            // Generating Access and Refresh Token
            const access_token = generateToken({ id: user.id });
            const refresh_token = generateToken({ id: user.id }, false);

            // Store the refresh token in the database
            const md5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            const [result] = await DB.execute(
                'INSERT INTO `refresh_tokens` (`user_id`,`token`) VALUES (?,?)',
                [user.id, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Failed to whitelist the refresh token.');
            }

            res.json({
                status: 200,
                access_token,
                refresh_token,
            });
        } catch (err) {
            next(err);
        }
    },

    userprofile: async (req, res, next) => {
        try {
            // Verify the access token
            const token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer ')) {
                return res.status(401).json({
                    status: 401,
                    message: 'Unauthorized: Access token is missing.',
                });
            }

            const accessToken = token.split(' ')[1];
            const data = verifyToken(accessToken);

            if (data?.status) {
                return res.status(data.status).json(data);
            }

            // Fetch user by the `id` (column)
            const user = await fetchUserByEmailOrID(data.id, false);

            if (user.length !== 1) {
                return res.status(404).json({
                    status: 404,
                    message: 'User not found',
                });
            }

            res.json({
                status: 200,
                user: user[0],
            });
        } catch (err) {
            next(err);
        }
    },

    refreshToken: async (req, res, next) => {
        try {
            const refreshToken = req.headers.refresh_token;
            if (!refreshToken) {
                return res.status(401).json({
                    status: 401,
                    message: 'Unauthorized: Refresh token is missing.',
                });
            }

            // Verify the refresh token
            const data = verifyToken(refreshToken, false);
            if (data?.status) {
                return res.status(data.status).json(data);
            }

            // Convert refresh token to MD5 format
            const md5Refresh = createHash('md5')
                .update(refreshToken)
                .digest('hex');

            // Find the refresh token in the database
            const [refTokenRow] = await DB.execute(
                'SELECT * FROM `refresh_tokens` WHERE token=?',
                [md5Refresh]
            );

            if (refTokenRow.length !== 1) {
                return res.status(401).json({
                    status: 401,
                    message: 'Unauthorized: Invalid Refresh Token.',
                });
            }

            // Generate new access and refresh tokens
            const access_token = generateToken({ id: data.id });
            const refresh_token = generateToken({ id: data.id }, false);

            const newMd5Refresh = createHash('md5')
                .update(refresh_token)
                .digest('hex');

            // Replace the old refresh token with the new refresh token
            const [result] = await DB.execute(
                'UPDATE `refresh_tokens` SET `token`=? WHERE `token`=?',
                [newMd5Refresh, md5Refresh]
            );

            if (!result.affectedRows) {
                throw new Error('Failed to whitelist the Refresh token.');
            }

            res.json({
                status: 200,
                access_token,
                refreshToken,
            });
        } catch (err) {
            next(err);
        }
    },
};

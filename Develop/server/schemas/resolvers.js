const { User } = require('../models');
const { AuthenticationError } = require('apollo-server-express');
const { signToken } = require('../utils/auth');

const resolvers = {
    Query: {
        me: async (parent, args, context) => {
            if (context.user) {
                const userData = await User.findOne({ _id: context.user._id })
                .select('-__v -password')

                return userData;
            }

            throw new AuthenticationError('User is not logged in');
        }
    },
    
    Mutation: {
        login: async (parent, { email, password }) => {
            const user = await User.findOne({ email });

            if (!user) {
                throw new AuthenticationError('Provided incorrect credentials');
            }

            const authPassword = await user.isCorrectPassword(password);

            if (!authPassword) {
                throw new AuthenticationError('Provided incorrect credentials');
            }

            const token = signToken(user);
            return { token, user };
        }
    }
}

module.exports = resolvers;
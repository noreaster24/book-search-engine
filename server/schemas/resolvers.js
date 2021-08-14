const { User } = require('../models');
const { AuthenticationError } = require('apollo-server-express');
const { signToken } = require('../utils/auth');

const resolvers = {
    Query: {
        me: async (parent, args, context) => {
            if (context.user) {
                const userData = await User.findOne({ _id: context.user._id })
                .select('-__v -password')
                .populate('savedBooks')

                return userData;
            }

            throw new AuthenticationError('User is not logged in');
        }
    },
    
    Mutation: {
        addUser: async (parent, args) => {
            const user = await User.create(args);
            const token = signToken(user)

            return { user, token }
        },

        login: async (parent, { email, password }) => {
            const user = await User.findOne({ email });

            if (!user) {
                throw new AuthenticationError('Incorrect username');
            }

            const authPassword = await user.isCorrectPassword(password);

            if (!authPassword) {
                throw new AuthenticationError('Incorrect password');
            }

            const token = signToken(user);
            return { token, user };
        },


        saveBook: async (parent, { bookData }, context) => {
            if (context.user) {
                const userData = await User.findByIdAndUpdate(
                    { _id: context.user._id },
                    { $push: { savedBooks: bookData } },
                    { new: true, runValidators: false }
                );

                return userData;
            }

            throw new AuthenticationError('You are not logged in')
        },

        removeBook: async (parent, { bookId }, context) => {
            if (context.user) {
                const userData = await User.findOneAndUpdate(
                    { _id: context.user._id },
                    { $pull: { savedBooks: { bookId: bookId } } },
                    { new: true, runValidators: true }
                );

                return userData;
            }

            throw new AuthenticationError('You are not logged in')
        }
    }
}

module.exports = resolvers;
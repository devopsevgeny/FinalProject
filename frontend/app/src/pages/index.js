import { configureStore } from '@reduxjs/toolkit'
import authReducer from './authSlice.js'
import { setTokenGetter } from '../api.js'

export const store = configureStore({ reducer: { auth: authReducer } })
setTokenGetter(() => store.getState().auth.token)

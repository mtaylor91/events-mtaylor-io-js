import sodium from 'libsodium-wrappers-sumo';
import axios from 'axios';
import type { AxiosResponse } from 'axios';
import IAM from 'iam-mtaylor-io-js';
import type { User } from 'iam-mtaylor-io-js';
import { v4 as uuidv4 } from 'uuid';

const DEFAULT_HOST = "events.mtaylor.io";
const DEFAULT_SECURE = true;


export interface ClientHello {
  user: string;
  session: string;
  token: string;
}


export default class Client {
  public url: string;
  public host: string;
  public secure: boolean;
  public iam: IAM;
  public socket: Socket;

  constructor(iam: IAM, host: string = DEFAULT_HOST, secure: boolean = DEFAULT_SECURE) {
    this.iam = iam;
    this.host = host;
    this.secure = secure;
    this.url = `${secure ? 'https' : 'http'}://${host}`;
    this.socket = new Socket(iam, host, secure);
  }

  public async connect(): Promise<Socket> {
    return await this.socket.connect();
  }

  async request(
    method: string,
    path: string,
    query: string | null = null,
    body: any | null = null,
  ): Promise<AxiosResponse> {
    const publicKey = this.iam.publicKey;
    const secretKey = this.iam.secretKey;
    const sessionToken = this.iam.sessionToken;

    if (!publicKey || !secretKey || !sessionToken) {
      throw new Error('IAM Client must be logged in');
    }

    const url = `${this.url}${path}${query ? `?${query}` : ''}`;
    const requestId = uuidv4();
    const publicKeyBase64 = sodium.to_base64(publicKey, sodium.base64_variants.URLSAFE);
    const signature = sodium.to_base64(sodium.crypto_sign_detached(
      this.requestStringToSign(method, path, query, requestId, sessionToken),
      secretKey), sodium.base64_variants.URLSAFE);

    const headers = {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': `Signature ${signature}`,
      'X-MTaylor-IO-User-ID': this.iam.userId,
      'X-MTaylor-IO-Public-Key': publicKeyBase64,
      'X-MTaylor-IO-Request-ID': requestId,
      'X-MTaylor-IO-Session-Token': sessionToken,
    };

    const response = await axios.request({
      method,
      url,
      headers,
      data: body,
    });

    return response;
  }

  requestStringToSign(
    method: string,
    path: string,
    query: string | null,
    requestId: string,
    sessionToken: string,
  ): Uint8Array {
    const parts = [
      method,
      this.host,
      path,
      query || '',
      requestId,
      sessionToken,
    ];

    return sodium.from_string(parts.join('\n'));
  }
}


export class Socket {
  public connected: boolean;
  public user: null | User;
  public url: string;

  public handlers: ((event: any) => void)[];

  private iam: IAM;
  private socket: null | WebSocket;

  constructor(iam: IAM, host: string = DEFAULT_HOST, secure: boolean = DEFAULT_SECURE) {
    this.connected = false;
    this.socket = null;
    this.user = null;
    this.iam = iam;
    this.url = `${secure ? 'wss' : 'ws'}://${host}`;
    this.handlers = [];
  }

  public async connect(): Promise<Socket> {
    const user = await this.iam.user.getUser()
    const session = this.iam.sessionId;
    const token = this.iam.sessionToken;

    if (!session) {
      throw new Error('Session ID not set');
    }

    if (!token) {
      throw new Error('Session token not set');
    }

    const connected = new Promise((resolve, reject) => {
      const socket = new WebSocket(this.url);
      this.connected = true;
      this.socket = socket;
      this.user = user;
      socket.binaryType = 'arraybuffer';
      socket.onmessage = e =>
        this.handlers.forEach(handler => handler(JSON.parse(e.data)));
      socket.onclose = this.onClose;
      socket.onerror = reject;
      socket.onopen = () => {
        console.log('websocket connected');
        socket.onerror = this.onError;
        const hello: ClientHello = { user: user.id, session, token };
        socket.send(JSON.stringify(hello));
        resolve(this);
      };
    });

    await connected;
    return this;
  }

  public disconnect() {
    console.log('disconnecting');
    if (this.socket) {
      this.socket.close();
    }
  }

  public publish(topic: string, data: any) {
    const id = uuidv4();
    const created = new Date().toISOString();
    this.send({ id, type: 'publish', topic, data, created });
  }

  public subscribe(topic: string) {
    this.send({ type: 'subscribe', topic });
  }

  public unsubscribe(topic: string) {
    this.send({ type: 'unsubscribe', topic });
  }

  public replay(topic: string) {
    this.send({ type: 'replay', topic });
  }

  public send(data: any) {
    if (!this.socket) {
      throw new Error('Socket is not connected');
    }

    this.socket.send(JSON.stringify(data));
  }

  public onClose(event: CloseEvent) {
    console.log('onClose', event);
    this.connected = false;
    this.socket = null;
  }

  public onError(error: any) {
    console.log('onError', error);
  }

  public onMessage(handler: (event: any) => void) {
    this.handlers.push(handler);
  }
}

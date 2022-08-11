import colors from 'colors/safe';
import { BuildSharesAction } from './BuildSharesAction';
import { KeyShares } from '../../lib/KeyShares/KeyShares';
import { getFilePath, writeFile } from '../../lib/helpers';
import { bigNumberValidator } from './validators/big-numbers';

export class BuildTransactionAction extends BuildSharesAction {
  static SSV_AMOUNT_ARGUMENT = {
    arg1: '-ssv',
    arg2: '--ssv-token-amount',
    options: {
      type: String,
      required: true,
      help: 'Token amount fee required for this transaction in Wei. ' +
        'Calculated as: totalFee := allOperatorsFee + networkYearlyFees + liquidationCollateral. '
    },
    interactive: {
      options: {
        type: 'text',
        validate: bigNumberValidator
      }
    }
  };

  static get options(): any {
    return {
      action: 'transaction',
      shortAction: 'tr',
      description: 'Generate shares for a list of operators from a validator keystore file and output registration transaction payload',
      arguments: [
        BuildTransactionAction.KEYSTORE_ARGUMENT,
        BuildTransactionAction.PASSWORD_ARGUMENT,
        BuildTransactionAction.OPERATORS_PUBLIC_KEYS_ARGUMENT,
        BuildTransactionAction.OPERATORS_IDS_ARGUMENT,
        BuildTransactionAction.SSV_AMOUNT_ARGUMENT,
      ],
    }
  }

  /**
   * Decrypt and return private key.
   */
  async execute(): Promise<any> {
    const {
      privateKey,
      operatorsIds,
      shares,
      operators,
    } = await this.dispatch();

    const { ssv_token_amount: ssvAmount } = this.args;

    // Step 4: build payload using encrypted shares
    const payload = await this.ssvKeys.buildPayload(
      privateKey,
      operatorsIds,
      shares,
      ssvAmount
    );

    const explainedPayload = '' +
      '\n[\n' +
      `\n\t validator public key   ➡️   ${payload[0]}\n` +
      `\n\t operators IDs          ➡️   array${payload[1]}\n` +
      '\n\t share public keys      ➡️   array[\n' +
      payload[2].map((publicKey: string, index: number) => `\n\t                                   [${index}]: ${publicKey}\n`).join('') +
      '                                 ]\n' +
      '\n\t share encrypted        ➡️   array[\n' +
      payload[3].map((privateKey: string, index: number) => `\n\t                                   [${index}]: ${privateKey}\n`).join('') +
      '                                 ]\n' +
      `\n\t ssv amount             ➡️   ${payload[4]}\n` +
      '\n]\n';

    const payloadFilePath = await getFilePath('payload');
    const message = '✳️  Transaction payload have the following structure encoded as ABI Params: \n' +
      '\n[\n' +
      '\n\tvalidatorPublicKey           ➡️   String\n' +
      '\n\toperatorsIDs                 ➡️   array[<operator ID>,         ..., <operator ID>]\n' +
      '\n\tsharePublicKeys              ➡️   array[<share public key>,    ..., <share public key>]\n' +
      '\n\tshareEncrypted               ➡️   array[<share private key>,   ..., <share private key>]\n' +
      '\n\tssvAmount                    ➡️   number in Wei\n' +
      '\n]\n\n' +
      '\n--------------------------------------------------------------------------------\n' +
      `\n✳️  Transaction explained payload data: \n${explainedPayload}\n` +
      '\n--------------------------------------------------------------------------------\n' +
      `\n✳️  regiserValidator() Transaction raw payload data: \n\n${payload}\n`;

    // Build keyshares file
    const operatorsData: any = [];
    operators.map((operator, index) => {
      operatorsData.push({
        id: operatorsIds[index],
        publicKey: operator,
      })
    });
    const ks = await KeyShares.fromData({
      version: 'v2',
      data: {
        publicKey: payload[0],
        operators: operatorsData,
        shares: {
          publicKeys: payload[2],
          encryptedKeys: payload[3],
        }
      }
    });
    await writeFile(payloadFilePath, ks.toString());
    return message + `\nSaved to file: ${colors.bgYellow(colors.black(payloadFilePath))}\n`;
  }
}

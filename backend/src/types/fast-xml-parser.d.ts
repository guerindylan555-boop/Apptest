declare module 'fast-xml-parser' {
  export interface X2jOptions {
    ignoreAttributes?: boolean;
    attributeNamePrefix?: string;
    textNodeName?: string;
    isArray?: (name: string, jpath: string) => boolean;
  }

  export class XMLParser {
    constructor(options?: X2jOptions);
    parse(xmlData: string | Buffer): any;
  }

  export class XMLBuilder {
    constructor(options?: any);
    build(data: any): string;
  }
}